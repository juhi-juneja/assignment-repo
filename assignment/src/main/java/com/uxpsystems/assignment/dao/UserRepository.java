package com.uxpsystems.assignment.dao;

import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.uxpsystems.assignment.dto.AccountStatus;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

	public Optional<User> findByUsername(String username);

	@Query("select u from User u where u.status = :status")
	Optional<List<User>> findAllActiveUsers(
			@Param("status") AccountStatus status);

	@Query("select u from User u where u.status = :status AND u.id = :id")
	public Optional<User> findActiveUserById(@Param("id") long id,@Param("status") AccountStatus status);

	@Transactional
	@Modifying(clearAutomatically = true)
	@Query("update User u set u.status = :status where u.id = :id")
	public void deactivateUserById(@Param("id") long id,@Param("status") AccountStatus status);
	
}
