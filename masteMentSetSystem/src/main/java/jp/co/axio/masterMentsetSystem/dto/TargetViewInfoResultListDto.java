package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 汎用CSV設定画面情報取得Dto
 *
 * @author jcbc
 */
@Setter
@Getter
public class TargetViewInfoResultListDto {

	/** No */
	public String dirNo;

	/** カラム論理名 */
	public String columnLogicalName;

	/** カラム物理名 */
	public String columnPhysicalName;
	
}