package com.example.springbootdemo.resource.controller;

import com.example.springbootdemo.resource.domain.gen.UserDO;
import com.example.springbootdemo.resource.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/")
public class LoginController {
    @Autowired
    UserService userService;

    @GetMapping("")
    public String root(){
        System.out.println("root()!!!");
        return "index";
    }

    @GetMapping("/index.html")
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

    @PostMapping("/shiroLogin")
    public ModelAndView shiroLogin(@RequestParam("username")String username,
                              @RequestParam("password")String password){
        ModelAndView mvc = new ModelAndView();
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
        try{
            subject.login(usernamePasswordToken);
            System.out.println("login success!!!");
            mvc.addObject("username",username);
            mvc.setViewName("main");
        }catch (AccountException accountException){
            System.err.printf("User %s Not Found!!!\n",username);
            mvc.setViewName("redirect:/index.html");
        }
        return mvc;
    }
}
