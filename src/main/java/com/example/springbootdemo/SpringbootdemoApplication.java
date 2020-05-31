package com.example.springbootdemo;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.Arrays;

/* @SpringBootApplication包含如下配置：
   @Configuration ： 将类标记为应用程序上下文的Bean定义的源
   @EnableAutoConfiguration ：告诉Spring Boot根据类路径设置,其他bean和各种属性设置开始添加bean.
   例如, 如果spring-webmvc在类路径上, 则此注释将应用程序标记为Web应用程序并激活关键行为,例如设置DispatcherServlet
   @ComponentScan ：告诉Spring在com/example包中寻找其他组件,配置和服务,让它找到控制器*/
@SpringBootApplication
//开启异步执行开关，可用@Async作用在类/方法上，使类中的所有方法或某个方法多线程执行
@EnableAsync
//扫描包下的所有Mapper接口类并注入为bean，无需在每一个Mapper接口类上使用注解@Mapper
@MapperScan("com.example.springbootdemo.resource.mapping")
public class SpringbootdemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringbootdemoApplication.class, args);
	}

	//@Bean
	public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
		//它检索由您的应用程序创建或由Spring Boot自动添加的所有bean, 它对它们进行排序并打印出来
		return args -> {

			System.out.println("Let's inspect the beans provided by Spring Boot:");

			String[] beanNames = ctx.getBeanDefinitionNames();
			Arrays.sort(beanNames);
			for (String beanName : beanNames) {
				System.out.println(beanName);
			}

		};
	}
}
