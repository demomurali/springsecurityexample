<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
</head>
<script>

function employeeInfo(event,id){
	console.log(event);
	console.log(id);
	event.preventDefault();
	var xhttp = new XMLHttpRequest();
	  xhttp.onreadystatechange = function() {
		  	alert(this.readyState);
		 	alert(this.responseText);
	    if (this.readyState == 4 && this.status == 200) {
	   
	     document.getElementById("employeeInfo").innerHTML = this.responseText;
	    }
	  };
	  xhttp.open("GET", "user/employeeDetails/employee?id="+id, true);
	  xhttp.send();
}


</script>
<body>
<a href="/home">home</a><br>
<a href="/user/list">list</a><br>
<a href="/logout">logout</a><br>

<h2>Employee Details</h2>
<table border="2" class="table table-striped table-bordered table-hover">
<tbody>
<tr>
	<td>Id</td>
	<td>Name</td>
	<td>Salary</td>
</tr>
<c:forEach items="${employees}" var="employee"> 
  <tr>
    <td><a href="" onclick="employeeInfo(event,${employee.employeeId})">${employee.employeeId}</a></td>
    <td>${employee.name}</td>
    <td>${employee.salary}</td>
  </tr>
</c:forEach>
</tbody>
</table>
<div id="employeeInfo">
</div>
</body>
</html>