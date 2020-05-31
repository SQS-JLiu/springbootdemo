package com.example.springbootdemo.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class HelloControllerTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void getHello() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/test/hello")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(equalTo("Greetings from Spring Boot!")));
    }

    /* MockMvc来自Spring Test，它使您可以通过一组方便的构建器类将HTTP请求发送到DispatcherServlet中，
    并对结果进行断言。 请注意使用@AutoConfigureMockMvc和@SpringBootTest来注入MockMvc实例。
    使用@SpringBootTest之后，我们要求创建整个应用程序上下文。
    一种替代方法是要求Spring Boot使用@WebMvcTest仅创建上下文的Web层。
    在这两种情况下，Spring Boot都会自动尝试查找应用程序的主应用程序类，但是如果您要构建其他内容，
    则可以覆盖它或缩小它的范围。 */
}
