package org.springframework.security.acls.neo4j.config;

import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.PermissionFactory;

@Configuration
public class SpringSecurityAclTestConfig {

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
