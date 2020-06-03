package com.example.springbootdemo.common.shiroconfig;

import com.example.springbootdemo.resource.domain.gen.UserDO;
import com.example.springbootdemo.resource.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.Serializable;

/**
 * 自定义的ShiroRealm继承AuthorizingRealm
 * 并且重写父类中的doGetAuthorizationInfo（权限相关）、
 * doGetAuthenticationInfo（身份认证）这两个方法
 */
public class ShiroRealm extends AuthorizingRealm {
    @Autowired
    private UserService userService;

    /**
     * 用于用户访问授权，判断用户可以访问的请求url --- 在配有缓存的情况下该方法只调用一次
     * 授权(验证权限时调用) 获取用户权限集合
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //若是不进行页面角色访问控制，直接返回null即可
        //return null;
        //在这个方法中主要是使用类：SimpleAuthorizationInfo进行角色的添加和权限的添加
        //权限信息对象info,用来存放查出的用户的所有的角色（role）及权限（permission）

        //这里获取的是doGetAuthenticationInfo()方法返回对象的第一个参数
        String username = (String) principalCollection.getPrimaryPrincipal();
        System.out.println("Shiro->doGetAuthorizationInfo():  username: "+username);
        //在这里 实际开发应该从数据库进行获取用户的角色和权限
        if(username.equals("admin")){
            SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
            //admin用户拥有admin、user角色
            info.addRole("admin");
            info.addRole("user");
            //设置该用户拥有query权限
            info.addStringPermission("user:query");
            return info;
        } else if(username.equals("123")){
            SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
            //设置该用户拥有user角色
            info.addRole("user");
            //设置该用户拥有query权限
            info.addStringPermission("user:query");
            return info;
        }else{
          return null;
        }
//        案例：
//        @Autowired
//        private LoginService loginService；
//        // 获取登录用户名
//        String name = (String) principalCollection.getPrimaryPrincipal();
//        // 查询用户名称
//        User user = loginService.findByName(name);
//        // 添加角色和权限
//        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
//        for (Role role : user.getRoles()) {
//            // 添加角色
//            simpleAuthorizationInfo.addRole(role.getRoleName());
//            for (Permission permission : role.getPermissions()) {
//                // 添加权限
//                simpleAuthorizationInfo.addStringPermission(permission.getPermission());
//            }
//        }
//        return simpleAuthorizationInfo;
    }

    /**
     * 用于验证用户登录
     * @param authenticationToken
     * @return SimpleAuthenticationInfo
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("Shiro->doGetAuthenticationInfo() 验证用户登录!!!");
        UsernamePasswordToken usernamePasswordToke = (UsernamePasswordToken) authenticationToken;
        String username = usernamePasswordToke.getUsername();
        char[] password = usernamePasswordToke.getPassword();
        String password2 = new String(password);
        //在这里从数据库中获取username用户的密码，然后验证是否和password相等
        //若不等则验证失败，抛出异常或返回null，若验证成功，则返回SimpleAuthenticationInfo
        //实际项目中，这里可以根据实际情况做缓存，如果不做，Shiro自己也是有时间间隔机制，2分钟内不会重复执行该方法
        UserDO userInfo = userService.getUserByUserName(username);
        if (userInfo == null) {
            throw new AccountException("用户名不正确");
        } else if (!userInfo.getPassword().equals(password2)) {
            throw new AccountException("密码不正确");
        }
        return new SimpleAuthenticationInfo(username,password,getName());
        //return new SimpleAuthenticationInfo(new ShiroUser("用户id","用户编码","用户名"),
        //        password,getName());

//        案例：
//        @Autowired
//        private LoginService loginService；
//        // 加这一步的目的是在Post请求的时候会先进认证，然后在到请求
//        if (authenticationToken.getPrincipal() == null) {
//            return null;
//        }
//        // 获取用户信息
//        String name = authenticationToken.getPrincipal().toString();
//        User user = loginService.findByName(name);
//        if (user == null) {
//            // 这里返回后会报出对应异常
//            return null;
//        } else {
//            // 这里验证authenticationToken和simpleAuthenticationInfo的信息
//            SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(name,
//                    user.getPassword().toString(), getName());
//            return simpleAuthenticationInfo;
//        }
    }

    /**
     * 自定义Authentication对象，使得Subject除了携带用户的登录名外还可以携带更多信息.
     */
    public static class ShiroUser implements Serializable {
        private static final long serialVersionUID = -6464464453425485277L;
        public String id;
        public String number;
        public String name;

        public ShiroUser(String userid, String number, String name) {
            this.id = userid;
            this.number = number;
            this.name = name;
        }

        public ShiroUser(String number, String name) {
            this.number = number;
            this.name = name;
        }

        public String getName() {
            return name;
        }

        /**
         * 本函数输出将作为默认的<shiro:principal/>输出.
         */
        @Override
        public String toString() {
            return number;
        }

        public String getDisplayName() {
            return name;
        }

    }
}
