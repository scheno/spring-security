package com.anonymous.security.order.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.anonymous.security.order.model.UserDTO;
import com.anonymous.security.order.common.EncryptUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Aiden
 * @date 2020/5/7
 * @version 1.0
 **/
//@Component
//public class TokenAuthenticationFilter extends OncePerRequestFilter {
//
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
//                                    FilterChain filterChain) throws ServletException, IOException {
//
//    }
//}

public class TokenAuthenticationFilter {

}
