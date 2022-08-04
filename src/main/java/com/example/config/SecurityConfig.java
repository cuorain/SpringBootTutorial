package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
public class SecurityConfig {

// WebSecurityConfigurerAdapterが非推奨になった。
//	@Override
//	public void configure(WebSecurity web) throws Exception{
//		// セキュリティを適用しない
//		web.ignoring()
//		.antMatchers("/webjars/**")
//		.antMatchers("/css/**")
//		.antMatchers("/js/**")
//		.antMatchers("/h2-console/**")
//	}
//
//	@Override
//	public void configure(HttpSecurity http) throws Exception{
//		// ログイン不要ページの設定
//		http.authorizeRequests()
//		.antMatchers("/login").permitAll()
//		.antMatchers("/user/signup").permitAll()
//		.anyRequest().authenticated();
//
//		// csrf対策を無効に（一時的に）
//		http.csrf().disable();
//	}


//	@Autowired
//	private UserDetailsService userDetailsService;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
		// ログイン不要ページの設定
		http.formLogin(login -> login
				.loginProcessingUrl("/login")
				.loginPage("/login")
				.defaultSuccessUrl("/user/list", true)
				.failureUrl("/login?error")
				.usernameParameter("userId")
				.passwordParameter("password")
				.permitAll()
		).logout(logout -> logout
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutUrl("/logout")
				.logoutSuccessUrl("/login?logout")
		).authorizeHttpRequests(authz -> authz
			.antMatchers("/login").permitAll()
			.antMatchers("/user/signup").permitAll()
			.antMatchers("/user/signup/rest").permitAll()
			.antMatchers("/admin").hasAuthority("ROLE_ADMIN")
			.antMatchers("/h2-console/**").permitAll()
			.mvcMatchers("/h2-console/**").permitAll()
			.mvcMatchers("/webjars/**").permitAll()
			.mvcMatchers("/css/**").permitAll()
			.mvcMatchers("/js/**").permitAll()
			.anyRequest().authenticated()
		);

		http.headers().frameOptions().disable();

		// csrf対策を無効に（一時的に）
		http.csrf().disable();

		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

//	@Bean
//	public InMemoryUserDetailsManager userDetailService() {
//		PasswordEncoder encoder = passwordEncoder();
//        User.UserBuilder userBuilder = User.builder().passwordEncoder(encoder::encode);
////		UserDetails general = userBuilder
////				.username("user")
////				.password("user")
////				.roles("GENERAL")
////				.build();
////		UserDetails admin = User
////				.withUsername("admin")
////				.password(encoder.encode("admin"))
////				.roles("ADMIN")
////				.build();
//		return new InMemoryUserDetailsManager(userBuilder.build());
//	}

}
