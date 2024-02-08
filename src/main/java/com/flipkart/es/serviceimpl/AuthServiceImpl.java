package com.flipkart.es.serviceimpl;

import java.util.Date;
import java.util.Random;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.flipkart.es.entity.Customer;
import com.flipkart.es.entity.Seller;
import com.flipkart.es.entity.User;
import com.flipkart.es.enums.UserRole;
import com.flipkart.es.exception.InvalidUserRoleException;
import com.flipkart.es.exception.UserVerifiedException;
import com.flipkart.es.repository.CustomerRepository;
import com.flipkart.es.repository.SellerRepository;
import com.flipkart.es.repository.UserRepository;
import com.flipkart.es.requestdto.OtpModel;
import com.flipkart.es.requestdto.UserRequest;
import com.flipkart.es.responsedto.UserResponse;
import com.flipkart.es.service.AuthService;
import com.flipkart.es.util.MessageStructure;
import com.flipkart.es.util.ResponseEntityProxy;
import com.flipkart.es.util.ResponseStructure;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

import com.flipkart.es.cache.*;
import com.flipkart.es.exception.*;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

	private UserRepository userRepository;
	private SellerRepository sellerRepository;
	private CustomerRepository customerRepository;
	private PasswordEncoder passwordEncoder;
	private CacheStore<String> otpCacheStore;
	private CacheStore<User> userCacheStore;
	private JavaMailSender javaMailSender;
	
	
	


	

	public User saveUser(User user) {

		if (user.getUserRole().equals(UserRole.SELLER)) {
			Seller seller = (Seller) user;
			return sellerRepository.save(seller);
		} else {
			Customer customer = (Customer) user;
			return customerRepository.save(customer);
		}
	}

	@Override
	public ResponseEntity<ResponseStructure<UserResponse>> registerUser(UserRequest userRequest) {

		

		// if (!UserRole.CUSTOMER.name().equals(userRequest.getUserRole().toUpperCase())) {
		// 	throw new InvalidUserRoleException("invalid user role");
		// }
		// if (!UserRole.SELLER.name().equals(userRequest.getUserRole().toUpperCase())) {
		// 	throw new InvalidUserRoleException("invalid user role");
		// }
		
		if (userRepository.existsByUserEmailAndIsEmailVerified(userRequest.getUserEmail(), true))
			throw new UserVerifiedException("user already registered and verified");
		
		
		String  OTP=generateOTP();
		User user=mapToRespectiveType(userRequest);
		userCacheStore.add(userRequest.getUserEmail(), user);
		otpCacheStore.add(userRequest.getUserEmail(),OTP);
		
		try
		{
			sendOtpToMail(user, OTP);
		}catch(MessagingException e)
		{
			log.error("The email address does not exsist");
		}
		
		
//		return new ResponseEntity<ResponseStructure<UserResponse>>(structure.setStatus(HttpStatus.ACCEPTED),
//				"Please verify through OTP",
//				mapToUserResponse(user));
		

//		User user = mapToRespectiveType(userRequest);
//
//		if (userRepository.existsByUserEmail(userRequest.getUserEmail())) {
//			// send otp and verify otp
//			// setEmailVerified as true and save it.
//		} else {
//			user = saveUser(user);
//		}
		return ResponseEntityProxy.setResponseStructure(HttpStatus.ACCEPTED,
				"Please verify through OTP sent on email ID",
				mapToUserResponse(user));
	}

	@Override
	public ResponseEntity<ResponseStructure<UserResponse>> verifyOTP(OtpModel otpModel) 
	{
		User user=userCacheStore.get(otpModel.getEmail());
		String otp=otpCacheStore.get(otpModel.getEmail());
		
		if(otp==null) throw new OtpExpiredException("OTP expired");
		if(user==null) throw new RegistrationSessionExpiredException("Registration session expired");
		if(!otp.equals(otpModel.getOtp())) throw new InvalidOtpException("Invalid OTP");
		
		user.setEmailVerified(true);
		userRepository.save(user);
		try
		{
			sendRegistrationSucessMail(user);
		}catch(MessagingException e)
		{
			log.error("The email address does not exsist");
		}
		
		
		 		return ResponseEntityProxy.setResponseStructure(HttpStatus.ACCEPTED,
				"user successfully Registered",
				mapToUserResponse(user));

		
	
		
	}
	
	private void sendOtpToMail(User user,String otp) throws MessagingException
	{
		
		sendMail(		MessageStructure.builder()
				.to(user.getUserEmail())
				.subject("Complete your Registration to Flipkart")
				.sentDate(new Date())
				.text("hey ,"+user.getUsername()
						+"Good to see you interested in flipkart,"
						+"Complete your registration using the OTP<br>"
						+"<h1>"+otp+"</h1><br>"
						+"Note:The OTP expires in 1 minute"
						+"<br><br>"
						+"with best regards<br>"
						+"Flipkart"
						).build());

		
	}
	
	private void sendRegistrationSucessMail(User user) throws MessagingException
	{
		
		sendMail(		MessageStructure.builder()
				.to(user.getUserEmail())
				.subject("Registration Successful,Welcome to Flipkart")
				.sentDate(new Date())
				.text("hey ,"+user.getUsername()
						+"Registration Successful,Welcome to Flipkart,"
						
						
						
						+"<br><br>"
						+"with best regards<br>"
						+"Flipkart"
						).build());

		
	}
	
	@Async
	private void sendMail(MessageStructure message) throws MessagingException
	{
		MimeMessage mimeMessage=javaMailSender.createMimeMessage();
		MimeMessageHelper helper=new MimeMessageHelper(mimeMessage, true);
		helper.setTo(message.getTo());
		helper.setSubject(message.getSubject());
		helper.setSentDate(message.getSentDate());
		helper.setText(message.getText(),true);
		javaMailSender.send(mimeMessage);
	}
	

	private String generateOTP() {
		
		return String.valueOf(new Random().nextInt(100000,999999));
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
	 

}
