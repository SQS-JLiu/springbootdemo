package com.example.springbootdemo.resource.service;

import com.example.springbootdemo.resource.domain.gen.UserDO;
import com.example.springbootdemo.resource.domain.gen.UserDOExample;
import com.example.springbootdemo.resource.mapping.gen.UserDOMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    @Autowired
    UserDOMapper userDOMapper;

    public UserDO getUserByUserName(String userName){
        UserDOExample userDOExample = new UserDOExample();
        userDOExample.or().andUsernameEqualTo(userName);
        List<UserDO>  list = userDOMapper.selectByExample(userDOExample);
        if(list.size() == 1){
           return list.get(0);
        }
        return null;
    }

    public UserDO getUserById(Integer id){
        return userDOMapper.selectByPrimaryKey(id);
    }
}
