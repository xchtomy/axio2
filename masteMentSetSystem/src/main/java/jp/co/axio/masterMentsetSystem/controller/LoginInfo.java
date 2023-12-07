package jp.co.axio.masterMentsetSystem.controller;

import java.util.List;

import javax.validation.constraints.NotBlank;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import lombok.Getter;
import lombok.Setter;

/**
 * ログイン情報
 * @author sa
 *
 */
@Setter
@Getter
public class LoginInfo {

	/**
	 * serialVersionUID
	 */
	@SuppressWarnings("unused")
	private static final long serialVersionUID = 1L;

	/**
	 * ログイン画面のユーザーID欄入力値
	 * (config.login.ldap.propDnAttrで指定した属性の値)
	 */
	@NotBlank
	private String inputId;

	/**
	 * パスワード
	 */
	@NotBlank
	private String pass;

	/**
	 * ログインユーザーID
	 * (ldap.uid, m_user.user_id)
	 */
	private String userId;

	/**
	 * 管理者フラグ true:管理者権限,false：利用者権限
	 */
	private Boolean isAdmin;

	/**
	 * ログインユーザー所属リスト
	 */
	private List<OrganizationInfo> organizationList;

	/**
	 * メッセージ
	 */
	private String errMessage;

//	/**
//	 * コンストラクタ
//	 * ユーザーの所属情報の保持が必要な場合、追加
//	 * @param inputId ログイン画面のユーザーID欄入力値(config.login.ldap.propDnAttrで指定した属性の値)
//	 * @param userId ログインユーザーID(ldap.uid, m_user.user_id)
//	 * @param isAdmin 管理者フラグ
//	 * @param organizationInfoList
//	 */
//	public LoginInfo(String inputId, String userId, Boolean isAdmin, List<OrganizationInfo> organizationInfoList) {
//		this.inputId = inputId;
//		this.userId = userId;
//		this.isAdmin = isAdmin;
//		this.organizationList = organizationInfoList;
//	}

	/**
	 * コンストラクタ
	 * @param inputId ログイン画面のユーザーID欄入力値(config.login.ldap.propDnAttrで指定した属性の値)
	 * @param userId ログインユーザーID(ldap.uid, m_user.user_id)
	 * @param isAdmin 管理者フラグ
	 */
	public LoginInfo(String inputId, String userId, Boolean isAdmin) {
		this.inputId = inputId;
		this.userId = userId;
		this.isAdmin = isAdmin;
	}

	/**
	 * コンストラクタ
	 */
	public LoginInfo() {
	}

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
	}
}
