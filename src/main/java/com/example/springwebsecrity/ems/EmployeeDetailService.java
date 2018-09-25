package com.example.springwebsecrity.ems;

import java.util.List;



public interface EmployeeDetailService {

	public List<Employee> getEmployeeDetails();
	public Employee insertEmployee(Employee employee);
	public Employee getEmployeeDetailById(int id);
}
