package com.example.springbootdemo.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;

import java.net.URL;

import static org.assertj.core.api.Assertions.*;

/* 除了模拟HTTP请求周期外，您还可以使用Spring Boot编写简单的全栈集成测试 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class HelloControllerIT {
    @LocalServerPort
    private int port;

    private URL base;

    @Autowired
    private TestRestTemplate template;

    /* 由于webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    嵌入式服务器从一个随机端口启动,并且在运行时使用@LocalServerPort发现了实际端口 */
    @BeforeEach
    public void setUp() throws Exception {
        this.base = new URL("http://localhost:" + port + "/test/hello");
    }

    @Test
    public void getHello() throws Exception {
        ResponseEntity<String> response = template.getForEntity(base.toString(),
                String.class);
        assertThat(response.getBody()).isEqualTo("Greetings from Spring Boot!");
    }
}
