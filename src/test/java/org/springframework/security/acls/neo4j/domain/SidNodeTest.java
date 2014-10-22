package org.springframework.security.acls.neo4j.domain;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.neo4j.graphdb.GraphDatabaseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.neo4j.conversion.Result;
import org.springframework.data.neo4j.support.Neo4jTemplate;
import org.springframework.security.acls.neo4j.config.SpringSecurityNeo4jTestConfig;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


@ContextConfiguration(classes={SpringSecurityNeo4jTestConfig.class})
@RunWith(SpringJUnit4ClassRunner.class)
@Transactional(readOnly=true)
public class SidNodeTest {

	@Autowired
	private GraphDatabaseService graphDatabaseService;
	
	private Neo4jTemplate neo4jTemplate;
	
	@Before
	public void init() {
		if(neo4jTemplate == null) {
			neo4jTemplate = new Neo4jTemplate(graphDatabaseService);
		}
	}
	
	@Test
	@Transactional(rollbackFor=Exception.class)
	public void test1Save() {
		SidNode sidNode = new SidNode();
		sidNode.setSid("ROLE_ADMIN");
		sidNode.setPrincipal(false);
		
		SidNode saved = neo4jTemplate.save(sidNode);
		assertNotNull(saved);
		assertNotNull(saved.getId());
		assertTrue(saved.equals(sidNode));
	}
	
	@Test
	public void test2Get() {
		SidNode sidNode = new SidNode();
		sidNode.setSid("testuser");
		sidNode.setPrincipal(true);
		
		SidNode saved = neo4jTemplate.save(sidNode);
		assertNotNull(saved);
		assertNotNull(saved.getId());
		
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("sid", "testuser");
		//params.put("type", SidNode.class.getName());
		
		String statement = "MATCH (s:SidNode) WHERE s.sid = {sid} RETURN s";
		//String statement = "start n=node:__types__(className=\"{type}\") return n";
		Result<Map<String, Object>> temp = neo4jTemplate.query(statement, params);
		
		Result<SidNode> result = temp.to(SidNode.class);
		
		assertNotNull(result);
		SidNode match = result.single();
		assertTrue(match.equals(saved));
		
	}
}
