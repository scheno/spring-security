package com.anonymous.security.order.controller;

import com.alibaba.fastjson.JSONObject;
import com.anonymous.security.order.model.UserDTO;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Aiden
 * @date 2020/5/7
 * @version 1.0
 **/
@RestController
public class OrderController {

    /**
     * 拥有p1权限方可访问此url
     * @return
     */
    @GetMapping(value = "/r/r1")
    @PreAuthorize("hasAuthority('p1')")
    public String r1(){
        //获取用户身份信息
        Object object = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        // UserDTO  userDTO = JSONObject.parseObject(object.toString(), UserDTO.class);
        return object.toString() + "访问资源1";
    }

    @GetMapping(value = "/r/r5")
    @PreAuthorize("hasAuthority('p8')")
    public String r5() {
        //获取用户身份信息
        Object object = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        UserDTO  userDTO = JSONObject.parseObject(object.toString(), UserDTO.class);
        return userDTO.getFullname()+"访问资源5";
    }

}