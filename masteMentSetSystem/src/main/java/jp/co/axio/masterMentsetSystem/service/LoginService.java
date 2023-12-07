package jp.co.axio.masterMentsetSystem.service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.ietf.ldap.LDAPAttribute;
import org.ietf.ldap.LDAPConnection;
import org.ietf.ldap.LDAPEntry;
import org.ietf.ldap.LDAPException;
import org.ietf.ldap.LDAPSearchResults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.LoginInfo;
import jp.co.axio.masterMentsetSystem.model.VLoginInfoEntity;
import jp.co.axio.masterMentsetSystem.repository.VLoginInfoEntityMapper;
import jp.co.axio.masterMentsetSystem.util.StringUtil;

/**
 * ログインサービス
 *
 * @author sa
 */
@Service
public class LoginService {

	/**
	 * 自処理名
	 */
	private static final String OWN_NAME = "LoginService";
	/**
	 * 自処理対象画面名
	 */
	private static final String OWN_TITLE = "ログイン処理";
	/**
	 * LDAP Protocol Version 3
	 */
	private static final int LDAP_V3 = 3; // LDAPv3
	/**
	 * ホスト名(application.propertiesより取得)
	 */
	@Value("${config.login.ldap.hostname}")
	private String propLdapHost;
	/**
	 * ポート(application.propertiesより取得)
	 */
	@Value("${config.login.ldap.port}")
	private int propPort;
	/**
	 * ベースDN(application.propertiesより取得)
	 */
	@Value("${config.login.ldap.dc}")
	private String propDc;
	/**
	 * 管理者DN(application.propertiesより取得)
	 */
	@Value("${config.login.ldap.managerDn}")
	private String propManagerDn;
	/**
	 * 管理者パスワード(application.propertiesより取得)
	 */
	@Value("${config.login.ldap.managerPass}")
	private String propManagerPass;
	/**
	 * ベースDN属性(application.propertiesより取得)
	 */
	@Value("${config.login.ldap.propDnAttr}")
	private String propDnAttr;
	/**
	 * 管理者フラグ:1
	 */
	private final String STRING_IS_ADMIN = "1";
	/**
	 * LDAPから取得する有効開始日・有効終了日の日付フォーマット
	 */
	private static final String DATE_PATTERN = "yyyy/MM/dd";
	/**
	 * ログイン情報取得用マッパー
	 */
	@Autowired
	private VLoginInfoEntityMapper vLoginInfoEntityMapper;
	/**
	 * メッセージソース
	 */
	@Autowired
	MessageSource ms;

	/**
	 * ログイン認証
	 * @param  form      画面Form
	 * @return LoginInfo ログイン成功の場合、ログイン情報(loginInfo)。取得できなかった場合、nullを返却。
	 * @throws Exception
	 */
	public LoginInfo authentication(LoginInfo form) throws Exception {
		LogService.info(OWN_TITLE, OWN_NAME, "LDAP認証", "開始");

		LDAPConnection lc = new LDAPConnection();
		try {
			// 接続
			ldapConnection(lc);

			// 管理者で認証(バインド)
			try {
				if (!ldapBind(lc, propManagerDn, propManagerPass.getBytes())) {
					// 管理者パスワードは正だが管理者認証できていない場合
					throw new LoginServiceManagerIsNotBoundException();
				} else {
					LogService.info(OWN_TITLE, OWN_NAME, "LDAP管理者認証", "bind成功");
				}
			} catch (LDAPException e) {
				LogService.info(OWN_TITLE, OWN_NAME, "LDAP管理者認証", "bind失敗");
				lc.disconnect();
				// 管理者bind()失敗時LDAPException.INVALID_CREDENTIALSが発生するが
				// (画面には認証エラーと表示させないで)独自のエラーメッセージを設定する
				if (LDAPException.INVALID_CREDENTIALS == ((LDAPException) e).getResultCode()) {
					throw new LoginServiceManagerInvalidCredentialsException();
				} else {
					// その他のLDAPExceptionはそのまま投げる
					throw e;
				}
			}
			// LDAP検索絞込条件
			String preFilter = propDnAttr + "=" + form.getInputId();
			// LDAP検索で取得する属性名の配列 属性は取得しない
			String[] attrs = { "axioModelAdminFlag", "axioStartDate", "axioExpireDate", "uid" };
			// LDAP検索
			LDAPSearchResults preResults = lc.search(
					propDc, // 検索ベース
					LDAPConnection.SCOPE_ONE, // 検索スコープ
					preFilter,
					attrs, // 属性は取得しない
					false // 属性名および属性値の取得
			);

			// 事前検索結果が存在しない場合
			// search()直後にLDAPSearchResults.getCount()を使用してはいけない
			// (結果を待たずに)正しくない件数を返す場合がある。
			// hasMore()使用後であればgetCount()は正しい値を返す。
			if (!preResults.hasMore()) {
				// 結果
				LogService.debug(OWN_TITLE, OWN_NAME, "LDAP事前検索", "エントリ取得結果: 0件");
				throw new LoginServiceNoEntryException();
			}
			// 取得結果エントリから有効期間内のものを抽出
			//			LDAPEntry preEntry = preResults.next();
			Map<String, Map<String, String>> validEntryMap = new HashMap<String, Map<String, String>>();
			while (preResults.hasMore()) {
				LDAPEntry preEntry = preResults.next();
				// エントリから情報取り出し
				Map<String, String> attrMap = getAttributeMap(preEntry, attrs);
				LogService.debug(OWN_TITLE, OWN_NAME, "LDAP検索", "エントリ取得結果:" + attrMap.toString());
				// 有効期間チェック
				LocalDate sysDate = LocalDate.now();
				if (isValidEntry(attrMap, sysDate)) {
					// エントリ保持用マップ追加
					String binddn = preEntry.getDN();
					validEntryMap.put(binddn, attrMap);
				}
			}
			LogService.debug(OWN_TITLE, OWN_NAME, "LDAP事前検索", "有効エントリ: " + validEntryMap.size() + "件");
			// 抽出結果が0件の場合
			if (validEntryMap.size() < 1) {
				throw new LoginServiceNoValidEntryException();
			}
			// 抽出結果が2件以上の場合
			if (validEntryMap.size() > 1) {
				throw new LoginServiceTooManyValidEntriesException();
			}
			// 以降、有効なエントリ(1件のみ想定)
			// DN取得
			String binddn = validEntryMap.keySet().stream().findFirst()
					// 何らかの理由でDNキーが取得できなかった場合は	NoSuchElementException
					.orElseThrow();
			byte[] bindpw = form.getPass().getBytes();

			// 認証(バインド)
			// パスワード不備でbind()失敗時、LDAPException.INVALID_CREDENTIALSが発生
			if (!ldapBind(lc, binddn, bindpw)) {
				LogService.info(OWN_TITLE, OWN_NAME, "LDAP認証", "bind失敗");
				throw new LoginServiceUserIsNotBoundException();
			} else {
				LogService.info(OWN_TITLE, OWN_NAME, "LDAP認証", "bind成功");
			}

			// エントリから情報取り出し
			Map<String, String> validEntryAttrMap = validEntryMap.get(binddn);
			String strAdminFlag = validEntryAttrMap.get(attrs[0]);
			String uid = validEntryAttrMap.get(attrs[3]);
			LogService.debug(OWN_TITLE, OWN_NAME, "LDAP検索", "エントリ取得結果:" + validEntryAttrMap.toString());

			Boolean isAdmin = STRING_IS_ADMIN.equals(strAdminFlag);

////ここから、ダミーソース開始
//			Boolean isAdmin = true;
//			String uid =  "91234";
////ダミーソース完了

			// DBから該当のユーザー情報を取得
			List<VLoginInfoEntity> vLoginInfoEntityList = selectVLoginInfo(uid);

			// 取得結果が存在しない場合
			if (vLoginInfoEntityList == null || vLoginInfoEntityList.size() == 0) {
				throw new LoginServiceNoUserDbRecordException();
			}
			// 取得結果が存在する場合、ログイン情報オブジェクト生成して返却
			LoginInfo loginInfo = createLoginInfo(form.getInputId(), uid, isAdmin, vLoginInfoEntityList);
			LogService.info(OWN_TITLE, OWN_NAME, "LDAP認証", "正常終了");

			return loginInfo;
		} finally {
			// 接続を切断する。
			lc.disconnect();
			LogService.debug(OWN_TITLE, OWN_NAME, "LDAP認証", "Disconnected");
		}
	}

	/**
	 * 有効期間をもとに有効
	 * @param attrMap エントリの属性Map<属性名,値>
	 * @param sysDate システム日付
	 * @return true:有効(該当ユーザーは有効期間内), false: 無効(該当ユーザーは有効期間外)
	 */
	private boolean isValidEntry(Map<String, String> attrMap, LocalDate sysDate) {
		boolean isValidEntry = false;
		String strStartDate = attrMap.get("axioStartDate");
		String strEndDate = attrMap.get("axioExpireDate");
		// 終了日補正：なかった場合、無期限として認識する
		if (StringUtil.isBlank(strEndDate)) {
			strEndDate = "2999/12/31";
		}
		LocalDate startDate = LocalDate.parse(strStartDate, DateTimeFormatter.ofPattern(DATE_PATTERN));
		LocalDate endDate = LocalDate.parse(strEndDate, DateTimeFormatter.ofPattern(DATE_PATTERN));
		// 有効期間によるログイン可否判定
		// 有効開始日<=システム日付<=有効終了日でない場合は、有効期間外
		if (sysDate.isBefore(startDate) || sysDate.isAfter(endDate)) {
			isValidEntry = false;
		} else {
			isValidEntry = true;
		}
		LogService.debug(OWN_TITLE, OWN_NAME, "LDAP検索",
				attrMap.get("uid") + "エントリ有効期間" + (isValidEntry ? "内":"外")
				+ ": startDate=" + strStartDate + ", endDate=" + strEndDate);
		return isValidEntry;
	}

	/**
	 * LDAP接続
	 * @param  lc     LDAP接続
	 * @throws Exception
	 */
	private void ldapConnection(LDAPConnection lc) throws Exception {
		// LDAP サーバに接続する。ホスト名・ポートはapplication.propertiesから取得。
		lc.connect(propLdapHost, propPort);
		LogService.debug(OWN_TITLE, OWN_NAME, "LDAP認証", "Connected to success : " + propLdapHost + ":" + propPort);
	}

	/**
	 * LDAP認証
	 * 指定された DN およびパスワードでバインド(認証)する。
	 * @param  lc      LDAP接続
	 * @param  binddn  バインドDN
	 * @param  bindpw  ユーザのパスワード(sha256)
	 * @return boolean true:バインド成功,false:バインド失敗
	 * @throws Exception
	 */
	private boolean ldapBind(LDAPConnection lc, String binddn, byte[] bindpw) throws Exception {

		lc.bind(LoginService.LDAP_V3, binddn, bindpw);
		LogService.debug(OWN_TITLE, OWN_NAME, "LDAP認証", "Bind success : " + binddn);

		// LDAP サーバに認証されたかどうかを確認する。
		// lc.bind() に間違ったパスワードを指定した場合、LDAPException
		// が throw されるが、その他の理由(期限切れなど)によって認証
		// されていない可能性もあるため、isBound() メソッドで確認する。
		return lc.isBound();
	}

	/**
	 * LDAPエントリから属性名、属性値のMapを取得
	 * @param  entry               LDAPエントリ
	 * @param  attrs               取得する属性の配列
	 * @return Map<String, String> Map<属性名, 属性値>
	 */
	private Map<String, String> getAttributeMap(LDAPEntry entry, String[] attrs) {
		HashMap<String, String> attrMap = new HashMap<String, String>();
		//ループ開始
		for (int i = 0; i < attrs.length; i++) {
			//String オブジェクトの配列内の属性の値を返す
			LDAPAttribute attribute = entry.getAttributeSet().getAttribute(attrs[i]);
			// 属性の値のうち1つ目を取得(各属性の値は1つのみの想定)
			// Map<属性名, 属性値>に追加
			if (attribute != null) {
				attrMap.put(attrs[i], Arrays.asList(attribute.getStringValueArray()).get(0));
			} else {
				// 属性項目未設定時、エラーをならないように
				attrMap.put(attrs[i], "");
			}
		}
		return attrMap;
	}

	/**
	 * ユーザーIDを元にDBからログイン情報を検索
	 * @param uid ログインユーザーID(ldap.uid, m_user.user_id)
	 * @return 検索結果
	 */
	@Transactional(readOnly = true)
	private List<VLoginInfoEntity> selectVLoginInfo(String uid) {
		List<VLoginInfoEntity> result = vLoginInfoEntityMapper.selectLoginInfoByUserId(uid);
		LogService.debug(OWN_TITLE, OWN_NAME, "ログインユーザー情報取得",
				"該当ユーザ情報取得結果件数:" + result == null ? "0" : String.valueOf(result.size()));
		return result;
	}

	/**
	 * ユーザーID、管理者フラグ、DBの取得結果をもとにログイン情報クラスを生成
	 * @param  inputId    ログイン画面のユーザーID欄入力値(config.login.ldap.propDnAttrで指定した属性の値)
	 * @param  userId     ログインユーザーID(ldap.uid, m_user.user_id)
	 * @param  isAdmin    true:管理者権限,false:利用者権限
	 * @param  entityList 該当ユーザーのログイン情報ビューのエンティティリスト
	 * @return LoginInfo  ログイン情報オブジェクト
	 * @throws Exception
	 */
	private LoginInfo createLoginInfo(String inputId, String userId, Boolean isAdmin, List<VLoginInfoEntity> entityList)
			throws Exception {
		// ユーザーの所属情報保持が必要な場合、追加
		//		// 所属組織リストに詰め替え
		//		List<OrganizationInfo> organizationInfoList = entityList.stream().map((VLoginInfoEntity entity) -> {
		//			// 所属組織情報生成
		//			OrganizationInfo org = new OrganizationInfo();
		//			org.setCompanyCode(entity.getCompanyCode());
		//			org.setOrganizationCode(entity.getOrganizationCode());
		//			org.setPositionCode(entity.getPositionCode());
		//			org.setIsHonmu(entity.isHonmu());//boolean
		//			return org;
		//		}).collect(Collectors.toList());
		// ログイン情報クラスに詰め替え
		LoginInfo loginInfo = new LoginInfo(inputId, userId, isAdmin);
		return loginInfo;
	}

	/**
	 * ログイン処理例外クラス
	 */
	public abstract class LoginServiceException extends Exception {
		/**
		 * コンストラクタ
		 * @param message メッセージ
		 */
		LoginServiceException(String message) {
			super(message);
		}
	}
	/**
	 * LDAP管理者認証失敗時(パスワード不正)
	 */
	private class LoginServiceManagerInvalidCredentialsException extends LoginServiceException {
		/**
		 * コンストラクタ
		 */
		LoginServiceManagerInvalidCredentialsException() {
			super(ms.getMessage("MSTO0009M0003", null, null));
		}
	}
	/**
	 * LDAP管理者認証失敗時(パスワード不正以外で認証できていない場合)
	 */
	private class LoginServiceManagerIsNotBoundException extends LoginServiceException {
		/**
		 * コンストラクタ
		 */
		LoginServiceManagerIsNotBoundException() {
			super(ms.getMessage("MSTO0009M0004", null, null));
		}
	}
	/**
	 * 画面ユーザーIDに紐づくLDAPエントリが0件の場合
	 */
	private class LoginServiceNoEntryException extends LoginServiceException {
		/**
		 * コンストラクタ
		 */
		LoginServiceNoEntryException() {
			super(ms.getMessage("MSTO0009M0005", null, null));
		}
	}
	/**
	 * 取得結果のうち有効期間内のエントリが0件の場合
	 */
	private class LoginServiceNoValidEntryException extends LoginServiceException {
		/**
		 * コンストラクタ
		 */
		LoginServiceNoValidEntryException() {
			super(ms.getMessage("MSTO0009M0006", null, null));
		}
	}
	/**
	 * 取得結果のうち有効期間内のエントリが2件以上の場合
	 */
	private class LoginServiceTooManyValidEntriesException extends LoginServiceException {
		/**
		 * コンストラクタ
		 */
		LoginServiceTooManyValidEntriesException() {
			super(ms.getMessage("MSTO0009M0007", null, null));
		}
	}
	/**
	 * LDAPユーザー認証失敗時(パスワード不正以外で認証できていない場合)
	 */
	private class LoginServiceUserIsNotBoundException extends LoginServiceException {
		/**
		 * コンストラクタ
		 */
		LoginServiceUserIsNotBoundException() {
			super(ms.getMessage("MSTO0009M0008", null, null));
		}
	}
	/**
	 * DBに該当のユーザーのログイン情報が存在しない場合
	 */
	private class LoginServiceNoUserDbRecordException extends LoginServiceException {
		/**
		 * コンストラクタ
		 */
		LoginServiceNoUserDbRecordException() {
			super(ms.getMessage("MSTO0009M0009", null, null));
		}
	}

}
