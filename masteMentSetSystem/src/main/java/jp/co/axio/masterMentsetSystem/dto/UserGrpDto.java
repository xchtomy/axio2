package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * ユーザシステムDto
 *
 * @author axio
 */

@Setter
@Getter
public class UserGrpDto {

	/** 利用システム */
	private String groupNameJp;
	/** 権限種別 */
	private String groupType;
	/** 区分 */
	private String rootType;

}
