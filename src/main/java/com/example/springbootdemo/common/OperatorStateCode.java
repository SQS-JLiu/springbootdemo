package com.example.springbootdemo.common;

public enum OperatorStateCode {
    COMMON_SUCCESS("200","ok"),
    COMMON_FAILED("0","failed"),

    APPLICATION_QUERY_ERROR("2001", "query application error"),
    APPLICATION_START_ERROR("2002", "query application error"),
    APPLICATION_STOP_ERROR("2003", "query application error"),


    TENANT_CREATE_ERROR("4001","create tenant error"),
    TENANT_DELETE_ERROR("4002","delete tenant error"),
    TENANT_UPDATE_ERROR("4003","update tenant error"),
    TENANT_SELECT_ERROR("4004","select tenant error"),
    TENANT_IMG_ERROR("4005","tenant img error"),


    PROJECT_DELETE_ERROR("5002","delete project error"),
    PROJECT_SELECT_ERROR("5004","select project error"),


    PROJECT_CATALOG_CREATE_ERROR("6001","create project catalog error"),
    PROJECT_CATALOG_DELETE_ERROR("6002","delete project catalog error"),
    PROJECT_CATALOG_UPDATE_ERROR("6003","update project catalog error"),
    PROJECT_CATALOG_SELECT_ERROR("6004","select project catalog error"),


    DELETE_K8S_CLUSTER_NODE_ERROR("7003","delete k8s cluster node error"),
    CLUSTER_DELETE_ERROR("7004","delete cluster error"),
    GET_CLUSTER_ERROR("7005","get cluster error"),
    DEPLOY_MONITOR_CLIENT_ERROR("7701","deploy monitor client error"),


    GET_DATA_CENTER_ERROR("8001","get data centers error"),


    GET_DOMAIN_TABLE_ERROR("9001","get domain table error"),


    FAILED_OPERATION("9998", "operation failed"),
    SUCCESS_OPERATION("9999", "operation success");

    private final String code;

    private final String msg;

    OperatorStateCode(String code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public String code() {
        return code;
    }

    public String msg() {
        return msg;
    }

}
