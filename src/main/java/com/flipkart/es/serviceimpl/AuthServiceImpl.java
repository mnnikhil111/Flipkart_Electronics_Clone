package com.flipkart.es.serviceimpl;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.EnumSet;
import java.util.Random;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.flipkart.es.cache.CacheStore;
import com.flipkart.es.entity.AccessToken;
import com.flipkart.es.entity.Customer;
import com.flipkart.es.entity.RefreshToken;
import com.flipkart.es.entity.Seller;
import com.flipkart.es.entity.User;
import com.flipkart.es.enums.UserRole;
import com.flipkart.es.exception.InvalidOTPException;
import com.flipkart.es.exception.InvalidUserRoleException;
import com.flipkart.es.exception.OTPExpiredException;
import com.flipkart.es.exception.RegistrationSessionExpiredException;
import com.flipkart.es.exception.UserRegisteredException;
import com.flipkart.es.repository.AccessTokenRepo;
import com.flipkart.es.repository.CustomerRepository;
import com.flipkart.es.repository.RefreshTokenRepo;
import com.flipkart.es.repository.SellerRepository;
import com.flipkart.es.repository.UserRepository;
import com.flipkart.es.requestdto.AuthRequest;
import com.flipkart.es.requestdto.OtpModel;
import com.flipkart.es.requestdto.UserRequest;
import com.flipkart.es.responsedto.AuthResponse;
import com.flipkart.es.responsedto.UserResponse;
import com.flipkart.es.security.JwtService;
import com.flipkart.es.service.AuthService;
import com.flipkart.es.util.CookieManager;
import com.flipkart.es.util.MessageStructure;
import com.flipkart.es.util.ResponseEntityProxy;
import com.flipkart.es.util.ResponseStructure;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.flipkart.es.responsedto.*;
import com.flipkart.es.requestdto.*;

@Slf4j
@Service

public class AuthServiceImpl implements AuthService {

	private UserRepository userRepository;
	private SellerRepository sellerRepository;
	private CustomerRepository customerRepository;
	private PasswordEncoder passwordEncoder;
	private CacheStore<String> otpCacheStore;
	private CacheStore<User> userCacheStore;
	private JavaMailSender javaMailSender;
	private AuthenticationManager authenticationManager;
	private CookieManager cookieManager;
	private JwtService jwtService;
	private AccessTokenRepo accessTokenRepo;
	private RefreshTokenRepo refreshTokenRepo;


	@Value("${myapp.access.expiry}")
	private int accessExpiryInSeconds;

	@Value("${myapp.refresh.expiry}")
	private int refreshExpiryInSeconds;



	public AuthServiceImpl(UserRepository userRepository, SellerRepository sellerRepository,
			CustomerRepository customerRepository, PasswordEncoder passwordEncoder, CacheStore<String> otpCacheStore,
			CacheStore<User> userCacheStore, JavaMailSender javaMailSender, AuthenticationManager authenticationManager,
			CookieManager cookieManager,JwtService jwtService,AccessTokenRepo accessTokenRepo,RefreshTokenRepo refreshTokenRepo) {
		super();
		this.userRepository = userRepository;
		this.sellerRepository = sellerRepository;
		this.customerRepository = customerRepository;
		this.passwordEncoder = passwordEncoder;
		this.otpCacheStore = otpCacheStore;
		this.userCacheStore = userCacheStore;
		this.javaMailSender = javaMailSender;
		this.authenticationManager = authenticationManager;
		this.cookieManager = cookieManager;
		this.jwtService=jwtService;
		this.accessTokenRepo=accessTokenRepo;
		this.refreshTokenRepo=refreshTokenRepo;
	}

	public User saveUser(User user) {

		user.setEmailVerified(true);

		if (user.getUserRole().equals(UserRole.SELLER)) {
			Seller seller = (Seller) user;
			return sellerRepository.save(seller);
		} else {
			Customer customer = (Customer) user;
			return customerRepository.save(customer);
		}
	}

	@SuppressWarnings("unchecked")
	private <T extends User> T mapToRespectiveType(UserRequest userRequest) {

		User user = null;
		switch (UserRole.valueOf(userRequest.getUserRole().toUpperCase())) {
		case SELLER -> {
			user = new Seller();
		}
		case CUSTOMER -> {
			user = new Customer();
		}
		default -> throw new InvalidUserRoleException("User not found with the specified role");
		}

		user.setUsername(userRequest.getUserEmail().split("@")[0].toString());
		user.setUserEmail(userRequest.getUserEmail());
		user.setUserPassword(passwordEncoder.encode(userRequest.getUserPassword()));
		user.setUserRole(UserRole.valueOf(userRequest.getUserRole().toUpperCase()));
		user.setEmailVerified(false);
		user.setDeleted(false);

		return (T) user;

	}

	private UserResponse mapToUserResponse(User user) {

		return UserResponse.builder()
				.userId(user.getUserId())
				.userEmail(user.getUserEmail())
				.username(user.getUsername())
				.userRole(user.getUserRole())
				.isDeleted(user.isDeleted())
				.isEmailVerified(user.isEmailVerified())
				.build();
	}

	private AuthResponse mapToAuthResponse(User user)
	{
		return AuthResponse.builder()
				.userId(user.getUserId())
				.username(user.getUsername())
				.Role(user.getUserRole().name())
				.isAuthenticated(true)
				.accessExpirationInSeconds(LocalDateTime.now().plusSeconds(accessExpiryInSeconds))
				.refreshExpirationInSeconds(LocalDateTime.now().plusSeconds(refreshExpiryInSeconds))
				.build();
	}

	private String generateOTP() {
		return String.valueOf(new Random().nextInt(111111, 999999));
	}

	private void sendOtpToMail(User user, String otp) throws MessagingException {
		sendMail(MessageStructure.builder()
				.to(user.getUserEmail())
				.subject("complete your registration to flipkart electronics")
				.sentDate(new Date())
				.text(
						"Hey " + user.getUsername()
						+ " Welcome to flipkart electronics, <br>"
						+ "Complete your registration using the OTP <br>"
						+ "<h1><strong> "+otp+" </strong></h1> <br>"
						+ "<br><br>"
						+ "Do not share this OTP with anyone"
						+ "<br><br>"
						+ "with best regards"
						+ "FlipKart electronics"
						)
				.build());
	}

	public void sendWelcomeMessage(User user) throws MessagingException{
		sendMail(MessageStructure.builder()
				.to(user.getUserEmail())
				.subject("Welcome to flipkart electronics")
				.sentDate(new Date())
				.text(
						"Hello " + user.getUsername()
						+ " we welcome you to flipkart electronics <br>"
						+ " we at flipkart do not call our customers for the password or band related issues <br><br>"
						+ " Beware of fraudsters"
						+ " Have a nice shopping"
						+ " with best regards"
						+ " Flipkart electronics"
						).build());


	}

	@Async
	private void sendMail(MessageStructure messageStructure) throws MessagingException {
		MimeMessage mimeMessage = javaMailSender.createMimeMessage();
		MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false);
		helper.setTo(messageStructure.getTo());
		helper.setSubject(messageStructure.getSubject());
		helper.setSentDate(messageStructure.getSentDate());
		helper.setText(messageStructure.getText(), true);
		javaMailSender.send(mimeMessage);
	}

	@Override
	public ResponseEntity<ResponseStructure<UserResponse>> registerUser(UserRequest userRequest) {

		try {
			if (!EnumSet.allOf(UserRole.class).contains(UserRole.valueOf(userRequest.getUserRole().toUpperCase()))) {
				throw new InvalidUserRoleException("user role invalid");
			}
		} catch (Exception e) {
			throw new InvalidUserRoleException("user role invalid");
		}

		if (userRepository.existsByUserEmail(userRequest.getUserEmail())) {
			throw new UserRegisteredException("user already registered");
		}
		User user = mapToRespectiveType(userRequest);

		String otp = generateOTP();
		userCacheStore.add(userRequest.getUserEmail(), user);
		otpCacheStore.add(userRequest.getUserEmail(), otp);

		try {
			sendOtpToMail(user, otp);
		} catch (MessagingException e) {
			log.error("the email address dosen't exist");
		}

		return ResponseEntityProxy.setResponseStructure(HttpStatus.ACCEPTED,
				"Please verify the otp sent to the email " + otp,
				mapToUserResponse(user));
	}

	@Override
	public ResponseEntity<ResponseStructure<UserResponse>> verifyOtp(OtpModel otpModel) {

		String otpFromCache = otpCacheStore.get(otpModel.getUserEmail());
		User user = userCacheStore.get(otpModel.getUserEmail());

		if (otpFromCache == null)
			throw new OTPExpiredException("otp expired");

		if (user == null)
			throw new RegistrationSessionExpiredException("registration session expired");

		if (!otpFromCache.equals(otpModel.getUserOTP()))
			throw new InvalidOTPException("invalid otp exception");

		user = saveUser(user);
		try {
			sendWelcomeMessage(user);
		} catch (MessagingException e) {
			log.error("something went wrong in send welcome message");
		}

		return ResponseEntityProxy.setResponseStructure(HttpStatus.CREATED,
				"user registered successfully", mapToUserResponse(user));

	}

	@Override
	public ResponseEntity<ResponseStructure<AuthResponse>> login(AuthRequest authRequest,HttpServletResponse httpServletResponse) {

		String username= authRequest.getUserEmail().split("@")[0];
		UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(username, authRequest.getUserPassword());
		Authentication authentication = authenticationManager.authenticate(token);
		if(!authentication.isAuthenticated())
			throw new UsernameNotFoundException("Failed to authenticate the user");
		
		return userRepository.findByUsername(username).map(user -> {
			grantAccess(httpServletResponse, user);
			
			return ResponseEntityProxy.setResponseStructure(HttpStatus.OK, "success", mapToAuthResponse(user));
		})
		.orElseThrow(() -> new UsernameNotFoundException("User name not found"));



		

	}

	private void grantAccess(HttpServletResponse response,User user)
	{
		String accessToken = jwtService.generateAccessToken(user.getUsername());
		String refreshToken = jwtService.generateRefreshToken(user.getUsername());


		response.addCookie(cookieManager.configure(new Cookie("at", accessToken),accessExpiryInSeconds));			
		response.addCookie(cookieManager.configure(new Cookie("rt", refreshToken),refreshExpiryInSeconds));

		accessTokenRepo.save(AccessToken.builder()
				.token(accessToken)
				.isBlocked(false)
				.expiration(LocalDateTime.now().plusSeconds(accessExpiryInSeconds))
				.build());

		refreshTokenRepo.save(RefreshToken.builder()
				.token(refreshToken)
				.isBlocked(false)
				.expiration(LocalDateTime.now().plusSeconds(refreshExpiryInSeconds))
				.build());


	}

}
