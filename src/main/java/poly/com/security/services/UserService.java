package poly.com.security.services;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import poly.com.entity.Employee;
import poly.com.repository.EmployeeRepository;
import poly.com.security.CustomUserDetails;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private EmployeeRepository employeeRepository;


    /* find by username
     * if user equal  null
     * return  Username not found exception
     * else return user  */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Employee employee = employeeRepository.findByUsername(username).orElse(null);
        if (employee == null) {
            throw new UsernameNotFoundException(username);
        }
        return new CustomUserDetails(employee);
    }
}
