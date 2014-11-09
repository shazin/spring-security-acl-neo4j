package org.springframework.security.acls.neo4j.config;

import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Configuration
@ComponentScan(basePackages = { "org.springframework.security.acls.neo4j" })
public class AppTestConfig {

	@Bean
	public AclAuthorizationStrategy aclAuthorizationStrategy() {
		return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority(
				"ROLE_SUPER_ADMIN"));
	}

	@Bean
	public PermissionGrantingStrategy permissionGrantingStrategy() {
		return new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger());
	}

	@Bean
	public PermissionFactory permissionFactory() {
		return new DefaultPermissionFactory();
	}

	@Bean
	public EhCacheBasedAclCache aclCache() {
		return new EhCacheBasedAclCache(ehCacheFactoryBean().getObject());
	}

	@Bean
	public EhCacheFactoryBean ehCacheFactoryBean() {
		EhCacheFactoryBean ehCacheFactoryBean = new EhCacheFactoryBean();

		ehCacheFactoryBean.setCacheManager(new EhCacheManagerFactoryBean()
				.getObject());
		ehCacheFactoryBean.setCacheName("aclCache");
		return ehCacheFactoryBean;
	}
}
