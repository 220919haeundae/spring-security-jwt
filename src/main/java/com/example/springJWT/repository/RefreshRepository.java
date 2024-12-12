package com.example.springJWT.repository;

import com.example.springJWT.entity.RefreshEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    Boolean existByRefresh(String refresh);

    @Transactional
    void deleteByRefresh(String refresh);
}
