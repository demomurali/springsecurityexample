package com.example.springwebsecrity.configuration;


import javax.annotation.Resource;
import javax.sql.DataSource;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;



//	url /user/	----> user
//	// /admin	---> admin user


// @Autowired
// @Inject



@Configuration
@EnableGlobalMethodSecurity(prePostEnabled=true, jsr250Enabled=true )
public class SecurityConfig extends WebSecurityConfigurerAdapter {    
	
	
	
	 @Autowired
	  private DataSource dataSource;

	  @Override
	  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		  
	    auth.jdbcAuthentication().dataSource(dataSource)
	        .usersByUsernameQuery("select username, password, enabled"
	            + " from users where username=?")
	        .authoritiesByUsernameQuery("select username, authority "
	            + "from authorities where username=?").passwordEncoder(new BCryptPasswordEncoder());
	  }
	
	
     protected void configure(HttpSecurity http) throws Exception {
    	 super.configure(http);
    	 
 
    
    
    
    	 
    	 http.authorizeRequests()
    		.antMatchers("/static/**").permitAll()
    		.antMatchers("/user/**").hasRole("USER")
         .antMatchers("/admin/**").hasRole("ADMIN")
        .and()
         .formLogin()
         .loginPage("/login")
         //.successForwardUrl("/home")
         .permitAll()
         .and()
         .logout()
         .permitAll();
     	}
  
 }
