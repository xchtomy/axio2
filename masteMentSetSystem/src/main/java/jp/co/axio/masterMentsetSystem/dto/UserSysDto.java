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
public class UserSysDto {

	/** 利用システム */
	private String sysName;
	/** 権限種別 */
	private String auth;
	/** 区分 */
	private String type;

}
