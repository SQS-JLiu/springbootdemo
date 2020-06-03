package com.example.springbootdemo.common.shiroconfig;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * springboot中集成shiro相对简单，只需要两个类：一个是shiroConfig类，一个是ShiroRealm类
 * 对shiro的一些配置，相对于之前的xml配置。包括：过滤的文件和权限，密码加密的算法，其用注解等相关功能。
 */
@Configuration
public class ShiroConfig {

    /**
     * Session Manager：会话管理
     * 即用户登录后就是一次会话，在没有退出之前，它的所有信息都在会话中；
     * 会话可以是普通JavaSE环境的，也可以是如Web环境的；
     */
    @Bean("sessionManager")
    public SessionManager sessionManager(){
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        //设置session过期时间
        sessionManager.setGlobalSessionTimeout(60 * 60 * 1000); //毫秒
        sessionManager.setSessionValidationSchedulerEnabled(true);
        sessionManager.setDeleteInvalidSessions(true);
        // 去掉shiro登录时url里的JSESSIONID
        sessionManager.setSessionIdUrlRewritingEnabled(false);
        return sessionManager;
    }

    /**
     * ShiroFilter是整个Shiro的入口点，用于拦截需要安全控制的请求进行处理
     */
    @Bean(name = "shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/index.html");  // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setSuccessUrl("/main.html");// 登录成功后要跳转的链接
        //shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");//设置无权限跳转页面，一般不生效,
        //在下面的simpleMappingExceptionResolver()方法中将异常做映射到unauthorized页面
        //拦截配置
        Map<String,String> filterChainDefinitionMap = new LinkedHashMap<String,String>();
        // 配置不会被拦截的链接, 按顺序判断
        // authc:所有url都必须认证通过才可以访问; anon:所有url都可以匿名访问
        filterChainDefinitionMap.put("/**/**.js", "anon");
        filterChainDefinitionMap.put("/**/**.css", "anon");
        filterChainDefinitionMap.put("/**/**.png", "anon");
        filterChainDefinitionMap.put("/**/**.jpg", "anon");
        filterChainDefinitionMap.put("/index.html", "anon");
        //filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/shiroLogin", "anon");
        //配置退出 过滤器,其中的具体的退出代码Shiro已经替我们实现了
        filterChainDefinitionMap.put("/logout", "logout");
        // 过滤链定义，从上向下顺序执行，一般将/**放在最为下边 --> 这是一个坑呢，一不小心代码就不好使了;
        // 这行代码必须放在所有权限设置的最后，不然会导致所有url都被拦截, 都需要认证
        filterChainDefinitionMap.put("/**", "authc");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    @Bean
    public ShiroRealm getShiroRealm(){
        return new ShiroRealm();
    }

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager defaultSecurityManager = new DefaultWebSecurityManager();
        defaultSecurityManager.setRealm(getShiroRealm());
        return defaultSecurityManager;
    }

    /**
     * 管理Shiro中一些bean的生命周期
     */
    @Bean("lifecycleBeanPostProcessor")
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }
    /**
     * 扫描上下文，寻找所有的Advistor(通知器）
     * 将这些Advisor应用到所有符合切入点的Bean中.
     * 注意，这个代理会是的每次doGetAuthorizationInfo()授权认证方法被多调用一次，也就是每次请求调用次数翻倍,
     * 可以注释掉这个注解
     */
    //@Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator proxyCreator = new DefaultAdvisorAutoProxyCreator();
        proxyCreator.setProxyTargetClass(true);
        return proxyCreator;
    }

    /**
     * 匹配所有加了 Shiro 认证注解的方法
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator daap = new DefaultAdvisorAutoProxyCreator();
        daap.setProxyTargetClass(true);
        return daap;
    }

    /**
     * shiro中如果使用注释来注入角色和权限的话，无法抛出UnauthorizedException的异常
     * 需要添加以下内容，当出现异常时，跳转至unauthorized.html。
     * 下面部分也可以不添加，就会跳转至默认的error.html界面。
     * 添加了下面的内容，可以指定跳转的页面。
     * @return SimpleMappingExceptionResolver
     */
    @Bean
    public SimpleMappingExceptionResolver simpleMappingExceptionResolver() {
        SimpleMappingExceptionResolver resolver = new SimpleMappingExceptionResolver();
        Properties properties = new Properties();
        //未授权的网页跳转至error.html
        properties.setProperty("org.apache.shiro.authz.UnauthorizedException", "/unauthorized");
        resolver.setExceptionMappings(properties);
        return resolver;
    }
}
