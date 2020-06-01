package com.example.springbootdemo.common;


public class ResponseMessage<T> {
	
	private T data;
	
	private String code;
	
	private String msg;

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public ResponseMessage() {
		super();
	}

	public ResponseMessage(T data, String code, String msg) {
		super();
		this.data = data;
		this.code = code;
		this.msg = msg;
	}
	
	public ResponseMessage(T data, OperatorStateCode opst) {
		this.data = data;
		this.code = opst.code();
		this.msg = opst.msg();
	}

	//静态方法需要<T>指明参数T是什么类型
	public static <T> ResponseMessage<T> ok(T t) {
		return new ResponseMessage(t,OperatorStateCode.COMMON_SUCCESS);
	}

	public static <T> ResponseMessage<T> failed() {
		return new ResponseMessage("{}",OperatorStateCode.COMMON_FAILED);
	}
}
