package com.example.springbootdemo.resource.controller;

import com.example.springbootdemo.resource.domain.gen.UserDO;
import com.example.springbootdemo.resource.service.UserService;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/getAll")
    public List<UserDO> getAllUsers(){
        return  userService.getAllUsers();
    }

    @GetMapping("/get/{page}")
    public List<UserDO> getUserPage(@PathVariable(value = "page",required = false) Integer pageNum){
        if(pageNum == 0){
            System.out.println("pageNum: "+pageNum);
            //使用PageHelper时每个PageHelper后面必须跟一个mybatis查询方法，这就是安全的.
            //因为PageHelper调用的是静态的方法，并且内部使用了ThreadLocal，必须被消费掉，否则会出现不安全问题.
            PageHelper.startPage(1,2);
        }else {
            PageHelper.startPage(pageNum,2);
        }
        System.out.println("user/get/"+pageNum);
        return userService.getAllUsers();
    }
}
