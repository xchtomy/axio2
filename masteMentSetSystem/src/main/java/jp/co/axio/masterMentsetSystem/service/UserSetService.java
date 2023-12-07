package jp.co.axio.masterMentsetSystem.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.UserSetForm;
import jp.co.axio.masterMentsetSystem.dto.UserAnnCmbOrgDto;
import jp.co.axio.masterMentsetSystem.dto.UserCareerInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserDetailDto;
import jp.co.axio.masterMentsetSystem.dto.UserGrpDto;
import jp.co.axio.masterMentsetSystem.dto.UserManCmbOrgDto;
import jp.co.axio.masterMentsetSystem.dto.UserOtherInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserPositionInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserSysDto;
import jp.co.axio.masterMentsetSystem.model.MUserOrgBeforeEntity;
import jp.co.axio.masterMentsetSystem.model.VGamenUserEntity;
import jp.co.axio.masterMentsetSystem.repository.VUserMapper;
import jp.co.axio.masterMentsetSystem.util.StringUtil;

/**
 * ユーザーサービスクラス
 *
 * @author AXIO
 * @version 1.0
 */
@Service
public class UserSetService {

	@Autowired
	VUserMapper vUserMapper;

	@Autowired
	UserSetOtherService userSetOtherService;

	// 権限区分 固定、「-」
	private static final String SYS_AUTH_TYPE_NONE = "-";
    // ONフラグ
	private static final String ON_FLG = "1";
	// 権限区分 固定、「有」
	private static final String SYS_AUTH_YES = "有";
	// 権限区分 固定、「有」
	private static final String SYS_AUTH_NO = "無";
    // デフォルト文字コード
    public static final String DEFAULT_CHAR_SET = "MS932";
    // 無効フラグ
	private static final String INACTIVE = "1";
	/* デフォルト改行コード */
    public static final String DEFAULT_LINEFEED = "\r\n";
    /** ダブルクオーテーション */
    public static final String DOUBLE_QUO = "\"";
	/* デフォルトセパレータ */
    public static final String DEFAULT_SEPARATOR = ",";
	/**
	* ユーザー詳細情報取得
	* @param form 画面の入力情報
	* @return List<VUserListEntity> 取得結果
	*/
	@Transactional
	public UserDetailDto getUserDetail(UserSetForm form, String userId) throws Exception {
		LogService.info("ユーザー詳細画面", "UserDetailDto", "ユーザー詳細情報取得", "開始");

		UserDetailDto res = null;

		VGamenUserEntity vo = new VGamenUserEntity();

		vo.setUserId(userId);

		vo = vUserMapper.getUser(vo);

		if (vo != null) {
			res = new UserDetailDto();

			// 名前（日本語）
			res.setNameJp(vo.getNameJp());
			// 名前（英語）
			res.setNameEn(vo.getSurnameEn() + " " + vo.getGivennameEn());
			// 在籍区分
			res.setEnrollmentName(vo.getEnrollmentName());
			// 社員番号
			res.setUserId(vo.getUserId());
			// 雇用区分
			res.setEmploymentName(vo.getEmploymentName());
			// 役職
			res.setPositionNameJp(vo.getPositionNameJp());
			// 部署名
			res.setOrganizationNameJp(vo.getOrganizationNameJp());
			// 会社コード
			res.setCompanyCode(vo.getCompanyCode());
			// 外線番号
			res.setTelEx(vo.getTelEx());
			// 内線番号
			res.setTel(vo.getTel());
			// 有効開始日
			res.setStartDate(dateToString(vo.getStartDate()));
			// 退職予定日
			res.setEndDate(dateToString(vo.getEndDate()));
			// ドメインアカウント
			res.setLoginId(vo.getLoginId());
			// 利用言語
			res.setLangName(vo.getLangName());
			// メールアドレス（メイン）
			res.setMailaddrNotification(vo.getMailaddrNotification());
			// メールアドレス（サブ）
			res.setMailaddr(vo.getMailaddr());

			form.setUserDetailDto(res);

			/**
			 * 権限情報
			 * 拡張枠
			 */
			// システム一覧
			// form.setUserSysList(getSysList(vo));
		}

		// セキュリティーグループ一覧
		List<UserGrpDto> userGrpList = new ArrayList<UserGrpDto>();

		userGrpList = vUserMapper.getUserGrp(userId);

		form.setUserGrpList(userGrpList);

		// 発令兼務一覧
		List<UserAnnCmbOrgDto> userAnnCmbOrgInfoList = new ArrayList<UserAnnCmbOrgDto>();

		userAnnCmbOrgInfoList = vUserMapper.getAnnCmbOrg(userId);

		form.setUserAnnCmbOrgInfoList(userAnnCmbOrgInfoList);

		// 手動兼務一覧
		List<UserManCmbOrgDto> userManCmbOrgInfoList = new ArrayList<UserManCmbOrgDto>();

		userManCmbOrgInfoList = vUserMapper.getManCmbOrg(userId);

		form.setUserManCmbOrgInfoList(userManCmbOrgInfoList);

		// セレクトリスト取得
		List<UserPositionInfoDto> userPositionInfoList = new ArrayList<UserPositionInfoDto>();

		userPositionInfoList = vUserMapper.getPosList();

		userPositionInfoList.add(0, new UserPositionInfoDto());

		form.setUserPositionInfoList(userPositionInfoList);

		// 経歴情報一覧
		List<UserCareerInfoDto> userCareerInfoList = new ArrayList<UserCareerInfoDto>();
		userCareerInfoList = vUserMapper.getCareerInfo(userId);
		// 前履歴の終了日を再編集、及び退職ケースの編集
		modifyEndDate(userCareerInfoList);

		form.setUserCareerInfoList(userCareerInfoList);

		/**
		 * その他属性は拡張属性のため、デフォルトは最小限の情報のみ出力
		 */

		// ユーザその他リスト取得
		List<UserOtherInfoDto> userOtherInfoList = userSetOtherService.userOtherInfoList(vo);

		form.setUserOtherInfoList(userOtherInfoList);

		LogService.info("ユーザー詳細画面", "UserDetailDto", "ユーザー詳細情報取得", "正常終了");

		return res;
	}

	/**
	 * 権限情報
	 * 拡張枠（システム権限）
	 * @param list
	 * @param sysFlg
	 * @param sysName
	 */
	private List<UserSysDto> getSysList(VGamenUserEntity vo) {
		// 戻り値
		List<UserSysDto> res = new ArrayList<UserSysDto>();

		ArrayList<String> atterFlgList = new ArrayList<String>();
		atterFlgList.add(vo.getExpansionAttr11());

		ArrayList<String> atterNameList = new ArrayList<String>();
		atterNameList.add("sample");

		for (int i = 0; i < atterFlgList.size(); i++) {

			UserSysDto UserSysDto = new UserSysDto();
			UserSysDto.setSysName(atterNameList.get(i));
			UserSysDto.setAuth(SYS_AUTH_TYPE_NONE); // 固定「-」

			if (ON_FLG.equals(atterFlgList.get(i))) {
				UserSysDto.setType(SYS_AUTH_YES); // 固定「有」
			} else {
				UserSysDto.setType(SYS_AUTH_NO); // 固定「無」

			}
			res.add(UserSysDto);
		}

		return res;
	}


	/**
	* ユーザー詳細保存
	* @param form 画面の入力情報
	* @return List<VUserListEntity> 取得結果
	*/
	@Transactional
	public boolean updateUserDetail(UserSetForm form, String loginId) throws Exception {
		LogService.info("ユーザー詳細画面", "UserSetForm", "ユーザー詳細保存", "開始");
        boolean res = true;

        // システム日付取得
		Calendar nowCal = Calendar.getInstance();
        // 操作者ID取得
		String userId = form.getUserDetailDto().getUserId();

        // 画面情報取得
		List<UserManCmbOrgDto> newlist = new ArrayList<UserManCmbOrgDto>();
		if (form.getUserManCmbOrgInfoList() != null) {
			newlist = form.getUserManCmbOrgInfoList();
		}

		// 既存データ抽出
		List<MUserOrgBeforeEntity> oldlist = new ArrayList<MUserOrgBeforeEntity>();
		oldlist = vUserMapper.getUserOrgBefore(userId);

		// 削除処理
		for (MUserOrgBeforeEntity oldVo : oldlist) {
			// 削除有無を判断する
			boolean delFlg = true;
			MUserOrgBeforeEntity deleteVo = new MUserOrgBeforeEntity();

			if (INACTIVE.equals(oldVo.getInvalidFlag())) {
				// 既に削除したレコードが比較対象外になる
				continue;
			}

			for (UserManCmbOrgDto newVo : newlist) {
				if (oldVo.getCompanyCode().equals(newVo.getCompanyCode()) &&
						oldVo.getOrganizationCode().equals(newVo.getOrganizationCode())) {
					delFlg = false;
					break;
				}
			}

			// 削除処理を行う
			if (delFlg) {
				BeanUtils.copyProperties(oldVo, deleteVo);
				deleteVo.setUpdaterId(loginId);
				deleteVo.setUpdateTs(nowCal.getTime());

				vUserMapper.delUserOrgBefore(deleteVo);
			}
		}

		// 新規追加処理
		for (UserManCmbOrgDto newVo : newlist) {
			boolean insertFLg = true;

			// 新規有無を判断する
			for (MUserOrgBeforeEntity oldVo : oldlist) {
				if (oldVo.getCompanyCode().equals(newVo.getCompanyCode()) &&
						oldVo.getOrganizationCode().equals(newVo.getOrganizationCode())) {
					insertFLg = false;
					break;
				}
			}

			// 新規処理を行う
			if (insertFLg) {
				SimpleDateFormat df = new SimpleDateFormat("yyyy/mm/dd");
				Date endDate = df.parse("2099/12/31");

				// 新規追加
				MUserOrgBeforeEntity insVo = new MUserOrgBeforeEntity();

				insVo.setUserId(userId);
				insVo.setCompanyCode(newVo.getCompanyCode());
				insVo.setOrganizationCode(newVo.getOrganizationCode());
				insVo.setStartDate(nowCal.getTime());
				insVo.setEndDate(endDate);
				insVo.setInvalidFlag("0");
				insVo.setOrganizationKbn("2");
				insVo.setLocationCode("jp");
				insVo.setRegisterId(loginId);
				insVo.setRegistTs(nowCal.getTime());
				insVo.setUpdaterId(loginId);
				insVo.setUpdateTs(nowCal.getTime());
				insVo.setPositionCode(newVo.getPositionCode());
				insVo.setConcurrencyOrder(null);

				vUserMapper.insUserOrgBefore(insVo);
			}
		}

		// 更新処理
		for (UserManCmbOrgDto newVo : newlist) {
			boolean updateFlg = false;
			MUserOrgBeforeEntity updateVo = new MUserOrgBeforeEntity();

			// 更新有無を判断する
			for (MUserOrgBeforeEntity oldVo : oldlist) {
				if (oldVo.getCompanyCode().equals(newVo.getCompanyCode()) &&
						oldVo.getOrganizationCode().equals(newVo.getOrganizationCode())) {

					// 職務変更あり
					boolean condition1 = !oldVo.getPositionCode().equals(newVo.getPositionCode());
					// 既に削除した
					boolean condition2 = INACTIVE.equals(oldVo.getInvalidFlag());

					if (condition1 || condition2) {
						// 職務変更あり
						updateFlg = true;

						BeanUtils.copyProperties(oldVo, updateVo);
						updateVo.setPositionCode(newVo.getPositionCode());
						updateVo.setInvalidFlag("0");
						updateVo.setUpdaterId(loginId);
						updateVo.setUpdateTs(nowCal.getTime());

						break;
					}
				}
			}

			// 更新処理を行う
			if (updateFlg) {
				vUserMapper.updUserOrgBefore(updateVo);
			}
		}

		LogService.info("ユーザー詳細画面", "UserSetForm", "ユーザー詳細保存", "正常終了");

		return res;
	}

	/**
	* ユーザー情報一覧検索
	* @param form 画面の入力情報
	* @return List<VUserListEntity> 取得結果
	*/
	@Transactional
	public File getCsvFile(UserSetForm form , String fileName) throws Exception {
		LogService.info("ユーザー検索一覧画面", "form", "CSVダウンロードファイル作成", "開始");

		OutputStreamWriter fw = null;
		File downloadFile = null;

		try {
			// CSVファイルを開く
			fw = new OutputStreamWriter(new FileOutputStream(fileName), DEFAULT_CHAR_SET);

			fw.write(makeOutputUserLine(form));

		} catch (Exception e) {
			e.printStackTrace();

		} finally {
			try {
				// CSVファイルを出力する。
				if (fw != null) {
					fw.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		downloadFile = new File(fileName);

		LogService.info("ユーザー検索一覧画面", "form", "CSVダウンロードファイル作成", "正常終了");
		return downloadFile;
	}

    /**
     * CSV、行作成
     *
     * @param csvData
     * @return
     */
    private String makeOutputUserLine(UserSetForm form){

    	StringBuffer text = new StringBuffer();

    	UserDetailDto userDetailDto = form.getUserDetailDto();

		text.append(getOutText("基本情報", false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("氏名(日本語)", true));
    	text.append(getOutText(userDetailDto.getNameJp(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("氏名（英語）", true));
    	text.append(getOutText(userDetailDto.getNameEn(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("在籍区分", true));
    	text.append(getOutText(userDetailDto.getEnrollmentName(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("社員番号", true));
    	text.append(getOutText(userDetailDto.getUserId(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("雇用区分", true));
    	text.append(getOutText(userDetailDto.getEmploymentName(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("役職", true));
    	text.append(getOutText(userDetailDto.getPositionNameJp(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("部署名", true));
    	text.append(getOutText(userDetailDto.getOrganizationNameJp(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("内線番号", true));
    	text.append(getOutText(userDetailDto.getTelEx(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("外線番号", true));
    	text.append(getOutText(userDetailDto.getTel(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("入社日", true));
    	text.append(getOutText(userDetailDto.getStartDate(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("退職日", true));
    	text.append(getOutText(userDetailDto.getEndDate(), false));
    	text.append(DEFAULT_LINEFEED);
    	text.append(DEFAULT_LINEFEED);

    	// 権限情報
    	text.append(getOutText("権限情報", false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("ドメインアカウント", true));
    	text.append(getOutText(userDetailDto.getLoginId(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("利用言語", true));
    	text.append(getOutText(userDetailDto.getLangName(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("メールアドレス（メイン）", true));
    	text.append(getOutText(userDetailDto.getMailaddrNotification(), false));
    	text.append(DEFAULT_LINEFEED);

    	text.append(getOutText("メールアドレス（サブ）", true));
    	text.append(getOutText(userDetailDto.getMailaddr(), false));
    	text.append(DEFAULT_LINEFEED);
		text.append(DEFAULT_LINEFEED);


		/**
		 * 拡張枠
		 */
		// 利用システム一覧
		// text.append(getOutText("利用システム一覧", true));
		// text.append(DEFAULT_LINEFEED);

		// text.append(getOutText("No", true));
		// text.append(getOutText("利用システム", true));
		// text.append(getOutText("権限種別", true));
		// text.append(getOutText("区分", true));
		// text.append(DEFAULT_LINEFEED);

		// List<UserSysDto> userSysList = form.getUserSysList();

		// for (int i = 0; i < userSysList.size(); i++) {

		// 	text.append(getOutText(String.valueOf(i + 1), true));
		// 	text.append(getOutText(userSysList.get(i).getSysName(), true));
		// 	text.append(getOutText(userSysList.get(i).getAuth(), true));
		// 	text.append(getOutText(userSysList.get(i).getType(), true));
		// 	text.append(DEFAULT_LINEFEED);
		// }

		// セキュリティグループ一覧
		text.append(getOutText("セキュリティグループ一覧", false));
		text.append(DEFAULT_LINEFEED);

		text.append(getOutText("No", true));
		text.append(getOutText("セキュリティグループ	", true));
		text.append(getOutText("権限種別", true));
		text.append(getOutText("区分", false));
		text.append(DEFAULT_LINEFEED);

		List<UserGrpDto> userGrpList = form.getUserGrpList();

		for (int i = 0; i < userGrpList.size(); i++) {
			text.append(getOutText(String.valueOf(i + 1), true));
			text.append(getOutText(userGrpList.get(i).getGroupNameJp(), true));
			text.append(getOutText(userGrpList.get(i).getGroupType(), true));
			text.append(getOutText(userGrpList.get(i).getRootType(), false));
			text.append(DEFAULT_LINEFEED);
		}

		text.append(DEFAULT_LINEFEED);

		// 兼務情報
		text.append(getOutText("兼務情報", false));
		text.append(DEFAULT_LINEFEED);

		// 発令兼務一覧
		text.append(getOutText("発令兼務一覧", false));
		text.append(DEFAULT_LINEFEED);

		text.append(getOutText("No", true));
		text.append(getOutText("会社コード	", true));
		text.append(getOutText("部署コード", true));
		text.append(getOutText("部署名", true));
		text.append(getOutText("兼務順", true));
		text.append(getOutText("役職", false));
		text.append(DEFAULT_LINEFEED);

		List<UserAnnCmbOrgDto> userAnnCmbOrgInfoList = form.getUserAnnCmbOrgInfoList();

		for (int i = 0; i < userAnnCmbOrgInfoList.size(); i++) {
			text.append(getOutText(String.valueOf(i + 1), true));
			text.append(getOutText(userAnnCmbOrgInfoList.get(i).getCompanyCode(), true));
			text.append(getOutText(userAnnCmbOrgInfoList.get(i).getOrganizationCode(), true));
			text.append(getOutText(userAnnCmbOrgInfoList.get(i).getOrganizationNameJp(), true));
			text.append(getOutText("-", true));
			text.append(getOutText(userAnnCmbOrgInfoList.get(i).getPositionNameJp(), false));
			text.append(DEFAULT_LINEFEED);
		}

		// 手動兼務一覧
		text.append(getOutText("手動兼務一覧", true));
		text.append(DEFAULT_LINEFEED);

		text.append(getOutText("No", true));
		text.append(getOutText("会社コード	", true));
		text.append(getOutText("部署コード", true));
		text.append(getOutText("部署名", true));
		text.append(getOutText("役職", false));
		text.append(DEFAULT_LINEFEED);

		List<UserManCmbOrgDto> userManCmbOrgInfoList = form.getUserManCmbOrgInfoList();

		for (int i = 0; i < userManCmbOrgInfoList.size(); i++) {
			text.append(getOutText(String.valueOf(i + 1), true));
			text.append(getOutText(userManCmbOrgInfoList.get(i).getCompanyCode(), true));
			text.append(getOutText(userManCmbOrgInfoList.get(i).getOrganizationCode(), true));
			text.append(getOutText(userManCmbOrgInfoList.get(i).getOrganizationNameJp(), true));
			text.append(getOutText(userManCmbOrgInfoList.get(i).getPositionNameJp(), false));
			text.append(DEFAULT_LINEFEED);
		}

		text.append(DEFAULT_LINEFEED);

		// 経歴情報一覧
		text.append(getOutText("経歴情報一覧", false));
		text.append(DEFAULT_LINEFEED);

		text.append(getOutText("No", true));
		text.append(getOutText("部署名", true));
		text.append(getOutText("有効開始日", true));
		text.append(getOutText("有効終了日", true));
		text.append(getOutText("役職", false));
		text.append(DEFAULT_LINEFEED);

		List<UserCareerInfoDto> userCareerInfoList = form.getUserCareerInfoList();

		for (int i = 0; i < userCareerInfoList.size(); i++) {
			text.append(getOutText(String.valueOf(i + 1), true));
			text.append(getOutText(userCareerInfoList.get(i).getOrganizationNameJp(), true));
			text.append(getOutText(userCareerInfoList.get(i).getStartDate(), true));
			text.append(getOutText(userCareerInfoList.get(i).getEndDate(), true));
			text.append(getOutText(userCareerInfoList.get(i).getPositionNameJp(), false));
			text.append(DEFAULT_LINEFEED);

		}

		text.append(DEFAULT_LINEFEED);

		// その他情報一覧
		text.append(getOutText("その他情報一覧", true));
		text.append(DEFAULT_LINEFEED);

		text.append(getOutText("項目名", true));
		text.append(getOutText("値", false));
		text.append(DEFAULT_LINEFEED);

		List<UserOtherInfoDto> userOtherInfoList = form.getUserOtherInfoList();

		for (UserOtherInfoDto vo:userOtherInfoList) {
			text.append(getOutText(vo.getColumnName(), true));
			text.append(getOutText(vo.getValueValue(), false));
			text.append(DEFAULT_LINEFEED);
		}

		return text.toString();
    }

	/**
	 * 前履歴終了日再編集
	 * @param userCareerInfoList
	 * @throws ParseException
	 */
	private void modifyEndDate(List<UserCareerInfoDto> userCareerInfoList) throws ParseException {

		// 前履歴終了日再編集
		for (int i = 0; i < userCareerInfoList.size() - 1 ; i++) {
			// 当履歴(i)
			UserCareerInfoDto vo = (UserCareerInfoDto) userCareerInfoList.get(i);
			// 前履歴(i+1)
			UserCareerInfoDto preVo = (UserCareerInfoDto) userCareerInfoList.get(i + 1);

			// 当履歴の開始日-1
			Calendar calendar = Calendar.getInstance();
	        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");

	        Date startDate = sdf.parse(vo.getStartDate());
	        calendar.setTime(startDate);
	        calendar.add(Calendar.DATE, -1);
			startDate = calendar.getTime();

			// 前履歴の終了日
			Date preEndDate = sdf.parse(preVo.getEndDate());

			if (preEndDate.before(startDate)) {
				// 離職ケース、処理なし
			} else {
				// 連続ケース
				preVo.setEndDate(new SimpleDateFormat("yyyy/MM/dd").format(startDate));
				userCareerInfoList.set(i + 1, preVo);
			}
		}

		// 退職の特殊処理
		UserCareerInfoDto firstData = (UserCareerInfoDto) userCareerInfoList.get(0);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
        Date startDate = sdf.parse(firstData.getStartDate());
        Date endDate = sdf.parse(firstData.getEndDate());
		if (startDate.after(endDate)) {
			// 退職後の行を削除
			userCareerInfoList.remove(0);
		}
	}

   /**
    *
    * @param val
    * @param addTab
    * @return
    */
    private String getOutText(String val,boolean addComma){
    	if(StringUtil.isNullBlank(val)){
    		val = "";
    	}

    	String retVal = StringUtil.trimSpace(val);

		// 「"」がある場合、前に「"」を付ける
		// 　データ：ｘｘｘ"AAA"	⇒ｘｘｘ""AAA""
		retVal = retVal.replaceAll("\"", "\"\"");
		// データ前後、無条件に「"」を付ける
		// 　データ：ｘｘｘｙｙｙ	⇒"ｘｘｘｙｙｙ"
		retVal = DOUBLE_QUO + retVal + DOUBLE_QUO;

    	if(addComma){
    		retVal = retVal + DEFAULT_SEPARATOR;
    	}

    	return  retVal;
    }

    /**
     * 日付型を日付文字列（yyyy/MM/dd）に変換する。
     *
     * @param dt - 日付（Date）
     * @return 日付文字列（String）
     */
    private String dateToString(Date dt) {
    	String result = "";

    	if (dt != null) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
			result = sdf.format(dt);
    	}

    	return result;
    }
}
