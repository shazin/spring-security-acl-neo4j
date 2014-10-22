package org.springframework.security.acls.neo4j.domain;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Iterator;
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

@ContextConfiguration(classes={SpringSecurityNeo4jTestConfig.class})
@RunWith(SpringJUnit4ClassRunner.class)
@Transactional(readOnly=true)
public class ClassNodeTest {
	
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
		ClassNode classNode = new ClassNode();
		classNode.setClassName("com.shazin.Test");
		ClassNode saved = neo4jTemplate.save(classNode);
		
		assertNotNull(saved);
		assertNotNull(saved.getId());
	}
	
	@Test
	@Transactional(rollbackFor=Exception.class)
	public void test2Get() {
		ClassNode classNode = new ClassNode();
		classNode.setClassName("com.shazin.Test2");
		ClassNode saved = neo4jTemplate.save(classNode);
		
		assertNotNull(saved.getId());
		
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("className", "com.shazin.Test2");
		
		String statement = "MATCH (c) WHERE c.className = {className} RETURN c";
		Result<Map<String, Object>> temp = neo4jTemplate.query(statement, params);
		
		Result<ClassNode> result = temp.to(ClassNode.class);
		
		assertNotNull(result);
		ClassNode match = result.single();
		assertTrue(match.equals(saved));
	}
	
	@Test
	@Transactional(rollbackFor=Exception.class)
	public void test3GetAll() {
		ClassNode classNode = new ClassNode();
		classNode.setClassName("com.shazin.TestClass1");
		ClassNode saved = neo4jTemplate.save(classNode);
		
		ClassNode classNode2 = new ClassNode();
		classNode2.setClassName("com.shazin.TestClass2");
		ClassNode saved2 = neo4jTemplate.save(classNode2);
		
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("className", "com.shazin.TestClass.*");
		
		String statement = "MATCH (c) WHERE c.className =~ {className} RETURN c";
		Result<Map<String, Object>> temp = neo4jTemplate.query(statement, params);
		
		Result<ClassNode> result = temp.to(ClassNode.class);
		
		assertNotNull(result);
		assertNotNull(result.iterator());
		assertTrue(result.iterator().hasNext());
		ClassNode node = null;
		Iterator<ClassNode> it = result.iterator();
		while(it.hasNext()) {
			node = it.next();
			System.out.println(node.getId() + " - " + node.getClassName());
		}

	}

}
