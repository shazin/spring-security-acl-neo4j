package org.springframework.security.acls.neo4j.model;

import java.util.UUID;

import org.springframework.data.neo4j.annotation.Indexed;
import org.springframework.data.neo4j.support.index.IndexType;

public class BaseNode {

	@Indexed(indexName = "id", indexType = IndexType.FULLTEXT)
	private final String id;

	public BaseNode() {
		this.id = UUID.randomUUID().toString();
	}

	public String getId() {
		return id;
	}

	public boolean equals(Object o) {
		if (o == null) {
			return false;
		}

		if (o == this) {
			return true;
		}

		if (o instanceof BaseNode) {
			BaseNode other = (BaseNode) o;
			return other.getId().equals(getId());
		}

		return false;
	}

	public String toString() {
		return "BaseNode[id=" + getId() + "]";
	}

	public int hashCode() {
		return getId().hashCode();
	}

}
