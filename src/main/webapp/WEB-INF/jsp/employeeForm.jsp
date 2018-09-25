<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
 <%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>   
    
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
</head>
<body class="container">
<a href="/home">home</a><br>
<a href="/admin/addEmployee">add</a><br>
<a href="/logout">logout</a><br>


<form:form method="POST" action="/springMvc/addEmployee.html"
  modelAttribute="employee">


	<div class="row">
            <div class="form-group col-md-12">
               <label class="col-md-3 " for="Id">Id</label>
               <div class="col-md-7">
                    <form:input type="text" path="employeeId"  class="form-control input-sm"/>
                    <div class="has-error">
                        <form:errors path="employeeId" class="text-danger"/>
                    </div>
                </div>
            </div>
        </div>
        
	<div class="row">
            <div class="form-group col-md-12">
               <label class="col-md-3 control-lable" for="username">Username</label>
               <div class="col-md-7">
                    <form:input type="text" path="name" id="username" class="form-control input-sm"/>
                    <div class="has-error">
                        <form:errors path="name" class="text-danger"/>
                    </div>
                </div>
            </div>
        </div>
    <div class="row">
            <div class="form-group col-md-12">
               <label class="col-md-3 control-lable" for="dob">DOB</label>
               <div class="col-md-7">
                    <form:input type="date" path="dob" id="dob" class="form-control input-sm"/>
                    <div class="has-error">
                        <form:errors path="dob" class="text-danger"/>
                    </div>
                </div>
            </div>
        </div>
 
    <div class="row">
            <div class="form-group col-md-12">
               <label class="col-md-3 control-lable" for="email">Email</label>
               <div class="col-md-7">
                    <form:input type="email" path="email" id="email" class="form-control input-sm"/>
                    <div class="has-error">
                        <form:errors path="email" class="text-danger"/>
                    </div>
                </div>
            </div>
        </div>
        
  
  <div class="row">
            <div class="form-group col-md-12">
               <label class="col-md-3 control-lable" for="designation">Designation</label>
               <div class="col-md-7">
                   <form:select path="designation" id="designation">
                        <form:option value="">Select Role</form:option>
                        <form:options items="${designations}" />
    					</form:select>
                    <div class="has-error">
                        <form:errors path="designation" class="text-danger"/>
                    </div>
                </div>
            </div>
        </div> 
   
    
      <div class="row">
            <div class="form-group col-md-12">
               <label class="col-md-3 control-lable" for="salary">Salary</label>
               <div class="col-md-7">
                    <form:input type="text" path="salary" id="salary" class="form-control input-sm"/>
                    <div class="has-error">
                        <form:errors path="salary" class="text-danger"/>
                    </div>
                </div>
            </div>
        </div> 
    <input type="submit" value="Submit" />

</form:form>
</body>
</html>