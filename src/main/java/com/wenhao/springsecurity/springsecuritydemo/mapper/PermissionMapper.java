package com.wenhao.springsecurity.springsecuritydemo.mapper;

import com.wenhao.springsecurity.springsecuritydemo.enity.Permission;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface PermissionMapper {

    // 查询苏所有权限
    @Select(" select * from sys_permission ")
    List<Permission> findAllPermission();

}
