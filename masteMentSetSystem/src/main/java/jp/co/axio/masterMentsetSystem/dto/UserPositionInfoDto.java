package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 役職リストDto
 *
 * @author axio
 */

@Setter
@Getter
public class UserPositionInfoDto {

	/** 役職コード */
	private String positionCode ;
	/** 役職名（日本語） */
	private String positionNameJp;

}
