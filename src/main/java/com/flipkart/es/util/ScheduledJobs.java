package com.flipkart.es.util;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.flipkart.es.entity.AccessToken;
import com.flipkart.es.entity.User;
import com.flipkart.es.repository.AccessTokenRepo;
import com.flipkart.es.repository.RefreshTokenRepo;
import com.flipkart.es.repository.UserRepository;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class ScheduledJobs {

    private UserRepository userRepository;
    private AccessTokenRepo accessTokenRepo;
    private RefreshTokenRepo refreshTokenRepo;
    
   

    @SuppressWarnings("null")
    @Scheduled(cron = "0 0 0 * * MON-SUN")
    public void deleteNonVerifiedUser() {
        List<User> listOfNonVerifiedUsers = userRepository.findByIsEmailVerified(false);
        userRepository.deleteAll(listOfNonVerifiedUsers);
    }
    
    @Scheduled(fixedDelay = 100001)
    public void CleanUpExpiredTokens()
    {
    	List<AccessToken> accessTokens=accessTokenRepo.findByAccessTokenExpirationBefore(LocalDateTime.now());
    	
    	for(AccessToken accessToken:accessTokens)
    	{
    		accessTokenRepo.delete(accessToken);
    	}
    	refreshTokenRepo.findByRefreshTokenExpirationBefore(LocalDateTime.now())
    	.forEach(refreshToken->{
    		refreshTokenRepo.delete(refreshToken);
    	});
    	
    	
    }

}
