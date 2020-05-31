package com.example.springbootdemo.resource.controller;

import com.example.springbootdemo.resource.domain.gen.UserDO;
import com.example.springbootdemo.resource.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/")
public class LoginController {
    @Autowired
    UserService userService;

    @RequestMapping("")
    public String root(){
        System.out.println("root()!!!");
        return "index";
    }

    @RequestMapping("/index.html")
    public String index(){
        System.out.println("index()!!!");
        return "index";
    }

    @PostMapping("/login")
    public ModelAndView login(@RequestParam("username")String username,
                        @RequestParam("password")String password){
        ModelAndView mvc = new ModelAndView();
        UserDO userDO = userService.getUserByUserName(username);
        if(userDO == null){
            System.err.printf("User %s Not Found!!!\n",username);
            mvc.setViewName("redirect:/index.html");
        } else if(password.equals(userDO.getPassword())){
            System.out.println("login!!!");
            mvc.addObject("username",username);
            mvc.setViewName("main");
        }else {
            mvc.setViewName("redirect:/index.html");
        }
        return mvc;
    }
}
