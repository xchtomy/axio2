package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import jp.co.axio.masterMentsetSystem.dto.UserAnnCmbOrgDto;
import jp.co.axio.masterMentsetSystem.dto.UserCareerInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserDetailDto;
import jp.co.axio.masterMentsetSystem.dto.UserGrpDto;
import jp.co.axio.masterMentsetSystem.dto.UserManCmbOrgDto;
import jp.co.axio.masterMentsetSystem.dto.UserOtherInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserPositionInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserSysDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserSetForm extends accessForm implements Serializable {

	/**
	 * ルール条件設定フォーム
	 */
	private static final long serialVersionUID = 1L;

	/** ユーザID */
	public UserDetailDto userDetailDto;

	/** Error message */
	public String errMessage;

	/** Error フラグ */
	public String errFlg;

	/** ユーザ名 */
	public UserListForm userListForm;

	/** ユーザシステムリスト */
	public List<UserSysDto> userSysList;

	/** セキュリティーグループリスト */
	public List<UserGrpDto> userGrpList;

	/** 発令兼務リスト */
	public List<UserAnnCmbOrgDto> userAnnCmbOrgInfoList;

    /** 手動兼務リスト */
	public List<UserManCmbOrgDto> userManCmbOrgInfoList;

	/** 職務リスト */
	public List<UserPositionInfoDto> userPositionInfoList;

	/** 経歴情報リスト */
	public List<UserCareerInfoDto> userCareerInfoList;

	/** ユーザその他Infoリスト */
	public List<UserOtherInfoDto> userOtherInfoList;

}
