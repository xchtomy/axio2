package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * max件数リストDto
 *
 * @author axio
 */

@Setter
@Getter
public class UserMaxCntDto {

	/** 件数コード */
	private String cntValue ;
	/** 件数名 */
	private String cntName;

}
