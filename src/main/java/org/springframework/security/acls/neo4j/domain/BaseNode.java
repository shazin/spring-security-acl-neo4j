package org.springframework.security.acls.neo4j.domain;

import java.util.UUID;

import org.springframework.data.neo4j.annotation.Indexed;
import org.springframework.data.neo4j.support.index.IndexType;

public class BaseNode {

	@Indexed(indexName="id", indexType=IndexType.FULLTEXT)
	private final String id;
	
	public BaseNode() {
		this.id = UUID.randomUUID().toString();
	}

	public String getId() {
		return id;
	}
	
	
}
