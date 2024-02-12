package com.flipkart.es.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.flipkart.es.entity.AccessToken;

public interface AccessTokenRepo extends JpaRepository<AccessToken, Long> {
	
	Optional<AccessToken> findByToken(String at);

	 List<AccessToken> findByAccessTokenExpirationBefore(LocalDateTime now); 
		// TODO Auto-generated method stub
		
	

}
