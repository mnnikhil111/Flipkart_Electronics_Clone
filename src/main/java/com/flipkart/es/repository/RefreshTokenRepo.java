package com.flipkart.es.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.flipkart.es.entity.AccessToken;
import com.flipkart.es.entity.RefreshToken;

public interface RefreshTokenRepo  extends JpaRepository<RefreshToken, Long> {

	Optional<RefreshToken> findByToken(String rt);
	
	List<RefreshToken> findByRefreshTokenExpirationBefore(LocalDateTime now);
}
