package com.example.springJWT.jwt;


import com.example.springJWT.dto.CustomUserDetails;
import com.example.springJWT.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 헤더에서 access 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김, 권한 확인이 필요치 않은 접근도 있기 때문
        if(accessToken == null) {
            filterChain.doFilter(request, response);

            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        // +) Spring Security는 설계 원칙 상 검증 시 단순하게 성공여부를 반환하기보다는,
        // 예외를 발생시켜 구체적인 실패 원인을 Exception message에 태워 알린다.
        // 따라서 isExpired의 반환타입이 Boolean이기는 하지만 실패 시 Exception이 발생하면서 catch 블럭이 실행된다.
        try {

            jwtUtil.isExpired(accessToken);

        } catch(ExpiredJwtException e) {

            // response body
            response.getWriter().print("access token expired");

            // response status code
            response.setStatus(HttpStatus.UNAUTHORIZED.value()); // == HttpServletResponse.SC_UNAUTHORIZED

            return;
        }

        // 토큰이 access인지 확인 (발급 시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if(!category.equals("access")) {

            //response body
            response.getWriter().print("invalid access token");

            //response status code
            response.setStatus(HttpStatus.UNAUTHORIZED.value()); // == HttpServletResponse.SC_UNAUTHORIZED

            return;
        }

        // username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);

    }


//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        // request에서 Authorization 헤더를 찾음
//        String authorization = request.getHeader("Authorization");
//
//        System.out.println(authorization);
//        // Authorization 헤더 검증
//        if(authorization == null || !authorization.startsWith("Bearer ")) {
//            System.out.println("token null");
//            filterChain.doFilter(request, response);
//
//            // 조건이 해당되면 메소드를 종료(필수)
//            return;
//        }
//
//        String token = authorization.split(" ")[1];
//
//        System.out.println(token);
//        // 토큰 소멸 시간 검증
//        if(jwtUtil.isExpired(token)) {
//
//            System.out.println("tocken expired");
//            filterChain.doFilter(request, response);
//
//            // 조건이 해당되면 메서드 종료(필수)
//            return;
//        }
//
//        // 토큰에서 username과 role 획득
//        String username = jwtUtil.getUsername(token);
//        String role = jwtUtil.getRole(token);
//
//        System.out.println(username);
//        System.out.println(role);
//
//        // userEntity를 생성하여 값을 set
//        UserEntity userEntity = new UserEntity();
//        userEntity.setUsername(username);
//        userEntity.setPassword("temppassword");
//        userEntity.setRole(role);
//
//        // UserDetails에 회원 정보 객체 담기
//        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);
//
//        // 스프링 시큐리티 인증 토큰 생성
//        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
//        // 세션에 사용자 등록
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        filterChain.doFilter(request, response);
//
//    }
}
