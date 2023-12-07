package jp.co.axio.masterMentsetSystem.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.UserListForm;
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
public class UserService {

	@Autowired
	VUserMapper vUserMapper;

    @Value("${config.userlist.maxcount}")
    private String maxCount;

	/* デフォルト改行コード */
    public static final String DEFAULT_LINEFEED = "\r\n";
    /* デフォルト文字コード */
    public static final String DEFAULT_CHAR_SET = "MS932";
	/* デフォルトセパレータ */
    public static final String DEFAULT_SEPARATOR = ",";
    /** ダブルクオーテーション */
    public static final String DOUBLE_QUO = "\"";

    /**
	 * メッセージソース
	 */
	@Autowired
	MessageSource ms;

	/**
	* ユーザー情報一覧検索
	* @param form 画面の入力情報
	* @return List<VUserListEntity> 取得結果
	*/
	@Transactional
	public void selectUserList(UserListForm form) throws Exception {
		LogService.info("ユーザー検索一覧画面", "UserList", "ユーザー一覧取得", "開始");

		if ("OK".equals(form.getCountCheck())) {
			// 画面再表示する時、confirmが非表示
			form.setPopupShowFlg("OFF");
			// 件数確認済みをクリア
			form.setCountCheck("");
            // 並び順設定
			setOrderCondition(form);

			List<VGamenUserEntity> userList = vUserMapper.selectUserList(form);

			if (userList != null && userList.size() > 0) {

				form.setZeroCntFlg("OFF");
				form.setDetailList(userList);
				form.setCsvFlg("ON");
				// 前後ページ制御、件数メッセージ設定
				this.setPageNo(form);
			} else {
				form.setZeroCntFlg("ON");
				form.setPrePageFlg("OFF");
				form.setNextPageFlg("OFF");
				form.setCsvFlg("OFF");
			}
		} else {
			// 該当するユーザ件数の確認
			String userCount = this.getUserCount(form);
			int num = Integer.parseInt(userCount);
		    // ワーニング上限件数
			int maxcnt = Integer.valueOf(maxCount);

			if (num > maxcnt) {
				// 件数確認ポップアップ画面表示
				form.setPopupShowFlg("ON");
				form.setPopupMsg(ms.getMessage("MSTO0013M0006", new String[] { String.valueOf(maxcnt) }, null));
				// 件数検索済み
				form.setCountCheck("OK");
			} else {
				// confirm未表示
				form.setPopupShowFlg("OFF");
				// 件数確認済みフラグをクリア
				form.setCountCheck("");
	            // 並び順設定
				setOrderCondition(form);

				List<VGamenUserEntity> userList = vUserMapper.selectUserList(form);

				if (userList != null && userList.size() > 0) {

					form.setZeroCntFlg("OFF");
					form.setPageNo("1");
					form.setDetailList(userList);
					form.setCsvFlg("ON");
					// 前後ページ制御、件数メッセージ設定
					this.setPageNo(form);

				} else {
					form.setZeroCntFlg("ON");
					form.setPrePageFlg("OFF");
					form.setNextPageFlg("OFF");
					form.setCsvFlg("OFF");
				}
			}
		}
		LogService.info("ユーザー検索一覧画面", "UserList", "ユーザー一覧取得", "正常終了");
	}

	/**
	* ユーザー件数取得
	* @param form 画面の入力情報
	* @return List<VUserListEntity> 取得結果
	*/
	@Transactional
	public String getUserCount(UserListForm form) throws Exception {
		LogService.info("ユーザー検索一覧画面", "UserList", "ユーザー件数取得", "開始");

		String count = vUserMapper.getUserCount(form);

		LogService.info("ユーザー検索一覧画面", "UserList", "ユーザー件数取得", "正常終了");
		return count;
	}

	/**
	* ユーザー情報一覧検索
	* @param form 画面の入力情報
	* @return List<VUserListEntity> 取得結果
	*/
	@Transactional
	public File getCsvFile(UserListForm form , String fileName) throws Exception {
		LogService.info("ユーザー検索一覧画面", "form", "CSVダウンロードファイル作成", "開始");

		OutputStreamWriter fw = null;
		File downloadFile = null;

		try {
			// CSVファイルを開く
			fw = new OutputStreamWriter(new FileOutputStream(fileName), DEFAULT_CHAR_SET);

			fw.write(makeCsvHeader());

			List<VGamenUserEntity> userList = vUserMapper.getCsvList(form);

			// ユーザ詳細情報をCSVに出力
			for (VGamenUserEntity vo : userList) {
				fw.write(makeOutputUserLine(vo));
			}
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
     * CSV、タイトル作成
     *
     * @param csvData
     * @return
     */
    private String makeCsvHeader(){

    	StringBuffer text = new StringBuffer();

		// 状態
    	text.append(getOutText("状態", true));
    	// ユーザーID
    	text.append(getOutText("ユーザーID", true));
    	// ログインID
    	text.append(getOutText("ログインID", true));
    	// 雇用名称
    	text.append(getOutText("雇用名称", true));
        // 氏名
    	text.append(getOutText("氏名", true));
    	// 英語姓
    	text.append(getOutText("英語姓", true));
    	// 英語名
    	text.append(getOutText("英語名", true));
    	// 所属部コード
    	text.append(getOutText("所属部コード", true));
        // 所属部署
    	text.append(getOutText("所属部署", true));
    	// 役職コード
    	text.append(getOutText("役職コード", true));
    	// 役職名
    	text.append(getOutText("役職名", true));
        // 有効開始日
    	text.append(getOutText("有効開始日", true));
    	// 有効終了日
    	text.append(getOutText("有効終了日", true));
    	// 会社コード
    	text.append(getOutText("会社コード", true));
    	// メールアドレス（メイン）
    	text.append(getOutText("メールアドレス（メイン）", true));
    	// メールアドレス（サブ）
    	text.append(getOutText("メールアドレス（サブ）", true));
    	// 外線番号
    	text.append(getOutText("外線番号", true));
    	// 内線番号
    	text.append(getOutText("内線番号", false));
        // 行末、改行
    	text.append(DEFAULT_LINEFEED);

    	return text.toString();
    }

    /**
     * CSV、行作成
     *
     * @param csvData
     * @return
     */
    private String makeOutputUserLine(VGamenUserEntity dto){

    	StringBuffer text = new StringBuffer();

		// 状態
    	text.append(getOutText(dto.getEnrollmentName(), true));
    	// ユーザーID
    	text.append(getOutText(dto.getUserId(), true));
    	// ログインID
    	text.append(getOutText(dto.getLoginId(), true));
    	// 雇用名称
    	text.append(getOutText(dto.getEmploymentName(), true));
        // 氏名
    	text.append(getOutText(dto.getNameJp(), true));
    	// 英語姓
    	text.append(getOutText(dto.getSurnameEn(), true));
    	// 英語名
    	text.append(getOutText(dto.getGivennameEn(), true));
    	// 所属部コード
    	text.append(getOutText(dto.getOrganizationCode(), true));
        // 所属部署
    	text.append(getOutText(dto.getOrganizationNameJp(), true));
    	// 役職コード
    	text.append(getOutText(dto.getPositionCode(), true));
    	// 役職名
    	text.append(getOutText(dto.getPositionNameJp(), true));
        // 有効開始日
    	text.append(getOutText(dateToString(dto.getStartDate()), true));
    	// 有効終了日
    	text.append(getOutText(dateToString(dto.getEndDate()), true));
    	// 会社コード
    	text.append(getOutText(dto.getCompanyCode(), true));
    	// メールアドレス（メイン）
    	text.append(getOutText(dto.getMailaddrNotification(), true));
    	// メールアドレス（サブ）
    	text.append(getOutText(dto.getMailaddr(), true));
    	// 外線番号
    	text.append(getOutText(dto.getTel(), true));
    	// 内線番号
    	text.append(getOutText(dto.getTelEx(), false));
        // 行末、改行
    	text.append(DEFAULT_LINEFEED);

    	return text.toString();
    }

	/**
	 * 表示件数メッセージ作成
	 *
	 * @param requestParams
	 * @throws Exception
	 * @throws NumberFormatException
	 *
	 *  */
	private void setPageNo(UserListForm form) throws NumberFormatException, Exception {
        // 最初ページ番号
		int fristPage = 0;
		// 最後ページ番号
		int lastpage = 0;

		// 検索結果件数
		String userCount = this.getUserCount(form);
		int count = Integer.parseInt(userCount);

		if (count > 0) {
			// 最初ページ番号
			fristPage = 1;

			// 最後ページ番号
			if (count / 10 >= 1) {
				lastpage = count / 10;
			}
			if (count % 10 > 0) {
				lastpage++;
			}
		}

		// 当ページ番号
		int currPage = Integer.parseInt(form.getPageNo());

		if (currPage > fristPage) {
			// 前ページ押下可
			form.setPrePageFlg("ON");
		} else {
			// 前ページ押下不可
			form.setPrePageFlg("OFF");
		}

		if (lastpage > currPage) {
			// 次のページ押下可
			form.setNextPageFlg("ON");
		} else {
			// 次のページ押下可
			form.setNextPageFlg("OFF");
		}

		//戻り値
		String cntMessage = "";

		Integer page = 0;

		if (count > 0) {

			page = currPage - 1;
            // 表示開始件数
			Integer start = page * 10 + 1;
            // 表示終了件数
			Integer end = start + 9;

			if (end > count) {
				end = count;
			}

			cntMessage = "全" + count + "件中 " + start + "件~" + end + "件を表示";
		}

		form.setCntMessage(cntMessage);
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

   /**
    * 検索並び順設定
    *
    * @param form
    */
	private void setOrderCondition(UserListForm form) {

		List<String> sortList = new ArrayList<String>();
		ArrayList<String> nameList = new ArrayList<String>();

		if (StringUtils.isNotBlank(form.getSortCondition())) {
			String[] tmpStr = form.getSortCondition().split(",");
			sortList = new ArrayList<String>( Arrays.asList(tmpStr));

		} else {
			// 検索ボタン押下した場合、初期化
			sortList.add("");
			sortList.add("");
			sortList.add("");
			sortList.add("");
			sortList.add("");
			sortList.add("");
			sortList.add("");
		}

		nameList.add("enrollment_name");
		nameList.add("user_id");
		nameList.add("login_id");
		nameList.add("employment_name");
		nameList.add("name_jp");
		nameList.add("position_name_jp");
		nameList.add("organization_name_jp");

		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i < sortList.size(); i++) {
            if(StringUtils.isNoneBlank(sortList.get(i))) {
            	// 空白以外、並び順を設定する。
    			buffer.append(nameList.get(i)).append(" ").append(sortList.get(i));
            }
		}

		// 初期はユーザーID順
		if (StringUtils.isBlank(buffer.toString())) {
			buffer.append("user_id ASC");
		} else if ((buffer.toString()).indexOf("user_id") < 0) {
			// 追加順：ユーザーIDの順
			buffer.append(", user_id ASC");
		}

		form.setOrderbyStr(buffer.toString());
	}
}
