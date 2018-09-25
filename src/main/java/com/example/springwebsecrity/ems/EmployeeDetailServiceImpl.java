package com.example.springwebsecrity.ems;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class EmployeeDetailServiceImpl implements EmployeeDetailService {

	@Autowired
	private EmployeeDetailDao employeeDetailsDao;
	
	public List<Employee> getEmployeeDetails() {
		return employeeDetailsDao.getEmployeeDetails();
	}

	public Employee insertEmployee(Employee employee) {
		return employeeDetailsDao.insertEmployee(employee);
	}
	
	public Employee getEmployeeDetailById(int id){
		return employeeDetailsDao.getEmployeeDetailById(id);
	}

}
