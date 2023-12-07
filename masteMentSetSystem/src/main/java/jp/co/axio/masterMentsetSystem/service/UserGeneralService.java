package jp.co.axio.masterMentsetSystem.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.UserListForm;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;
import jp.co.axio.masterMentsetSystem.model.VGamenUserEntity;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstSelectMapper;
import jp.co.axio.masterMentsetSystem.repository.VUserMapper;
import jp.co.axio.masterMentsetSystem.util.StringUtil;

/**
 * ユーザーサービスクラス(一般ユーザー)
 *
 * @author AXIO
 * @version 1.0
 */
@Service
public class UserGeneralService {

	@Autowired
	VUserMapper vUserMapper;

	@Autowired
	MgpCodeMstSelectMapper mgpCodeMstMapper;

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
    /** 汎用コードマスタの役職名称出力マスタのクラスコード */
    public static final String POSITION_CODE = "00015";

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

		// 汎用コードマスタに定義した役職コード一覧を取得する
		List<MgpCodeMst> mgpCodeList = mgpCodeMstMapper.selectMgpCodeMstSearchByGpuMasterSet(POSITION_CODE);

		// 最大表示件数の設定
		form.setCntInt(Integer.parseInt(form.getCntSelected()));

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

				// 表示項目の編集
				for (int i = 0; i < userList.size(); i++) {
					// 所属部署の後ろ、派遣元会社情報を追加する
					if (StringUtil.isNotBlank(userList.get(i).getExpansionAttr37())) {
						userList.get(i).setOrganizationNameJp(userList.get(i).getOrganizationNameJp()
								+ " " + userList.get(i).getExpansionAttr37());
					}
					// 汎用コードマスタに定義した役職コードのみ、役職名称を出力する
					boolean notFoundFlag = true;
					for (int j = 0; j < mgpCodeList.size(); j++) {
						if ((mgpCodeList.get(j).getValue1()).equals(userList.get(i).getPositionCode())) {
							notFoundFlag = false;
							break;
						}
					}
					if (notFoundFlag) {
						// 役職名称が非表示
						userList.get(i).setPositionNameJp("");
					}
				}
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

					// 表示項目の編集
					for (int i = 0; i < userList.size(); i++) {
						// 所属部署の後ろ、派遣元会社情報を追加する
						if (StringUtil.isNotBlank(userList.get(i).getExpansionAttr37())) {
							userList.get(i).setOrganizationNameJp(userList.get(i).getOrganizationNameJp()
									+ " " + userList.get(i).getExpansionAttr37());
						}
						// 汎用コードマスタに定義した役職コードのみ、役職名称を出力する
						boolean notFoundFlag = true;
						for (int j = 0; j < mgpCodeList.size(); j++) {
							if ((mgpCodeList.get(j).getValue1()).equals(userList.get(i).getPositionCode())) {
								notFoundFlag = false;
								break;
							}
						}
						if (notFoundFlag) {
							// 役職名称が非表示
							userList.get(i).setPositionNameJp("");
						}
					}
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

		// 選択したページ件数
		int maxCnt = Integer.parseInt(form.getCntSelected());

		if (count > 0) {
			// 最初ページ番号
			fristPage = 1;

			// 最後ページ番号
			if (count / maxCnt >= 1) {
				lastpage = count / maxCnt;
			}
			if (count % maxCnt > 0) {
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
			Integer start = page * maxCnt + 1;
            // 表示終了件数
			Integer end = start + maxCnt -1;

			if (end > count) {
				end = count;
			}

			cntMessage = "全" + count + "件中 " + start + "件~" + end + "件を表示";
		}

		form.setCntMessage(cntMessage);
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

		nameList.add("organization_code");
		nameList.add("name_kana");
		nameList.add("name_jp");
		nameList.add("name_en");
		nameList.add("position_name_jp");
		nameList.add("expansion_attr36");
		nameList.add("tel_ex");

		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i < sortList.size(); i++) {
            if(StringUtils.isNoneBlank(sortList.get(i))) {
            	// 空白以外、並び順を設定する。
    			buffer.append(nameList.get(i)).append(" ").append(sortList.get(i));
    			// 追加順：ユーザーIDの順
    			buffer.append(", user_id ASC");
            }
		}

		// 初期は組織コード順
		if (StringUtils.isBlank(buffer.toString())) {
			buffer.append("organization_code ASC, user_id ASC");
		}
		form.setOrderbyStr(buffer.toString());
	}
}
