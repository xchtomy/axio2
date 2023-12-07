package jp.co.axio.masterMentsetSystem.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthOrgCodeListController;
import jp.co.axio.masterMentsetSystem.controller.AuthUserCodeListController;
import jp.co.axio.masterMentsetSystem.dto.AuthUserCodeListDto;
import jp.co.axio.masterMentsetSystem.model.VGamenUserEntity;
import jp.co.axio.masterMentsetSystem.repository.VUserMapper;

/**
 * ユーザーID一覧画面サービスクラス
 *
 * @author axio
 * @version 1.0
 */
@Service
public class AuthUserCodeListService {

    /* 役職マスタ */
    @Autowired
    VUserMapper vUserMapper;

    /**
     * ユーザー情報検索処理
     *
     * @param selectedCodeMapList - 選択済みコードのマップリスト（List<Map<String, String>>）
     * @param checkedCodeMapList - チェックコードのマップリスト（List<Map<String, String>>）
     * @param searchFlag - true:検索条件の検索をする／false:検索条件の検索をしない（選択済みのユーザーのみ）（boolean）
     * @param searchUserCode - 検索するユーザーID（String）
     * @param searchUserName - 検索するユーザー氏名（String）
     * @param searchStartDateYmd - 検索する有効基準日（String）
     * @param searchEndDateYmd - 未使用（String）
     * @return 役職情報リスト（List<AuthUserCodeListDto>）
     */
    @Transactional
    public List<AuthUserCodeListDto> selectVUser(List<Map<String, String>> selectedCodeMapList
    												, List<Map<String, String>> checkedCodeMapList
    												, boolean searchFlag
    												, String searchUserCode
    												, String searchUserName
    												, String searchStartDateYmd
    												, String searchEndDateYmd) {
		List<AuthUserCodeListDto> result = new ArrayList<AuthUserCodeListDto>();
        LogService.info(AuthUserCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "ユーザー情報検索処理", "開始");

        List<VGamenUserEntity> vUserListEntityList = null;
        if (selectedCodeMapList == null) selectedCodeMapList = new ArrayList<Map<String, String>>();
        if (checkedCodeMapList == null) checkedCodeMapList = new ArrayList<Map<String, String>>();
        if (searchUserCode == null) searchUserCode = "";
        if (searchUserName == null) searchUserName = "";
        if (searchStartDateYmd == null) searchStartDateYmd = "";
        if (searchEndDateYmd == null) searchEndDateYmd = "";

        Set<String> selectedCodeSet = new HashSet<String>();
		Set<String> checkedCodeSet = new HashSet<String>();
        List<Map<String, String>> codeMapList = new ArrayList<Map<String, String>>();
        for (Map<String, String> map:selectedCodeMapList) {
        	if (map != null
//        			&& map.containsKey(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY1)
        			&& map.containsKey(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY2)) {
        		String val = new StringBuffer()
//									.append(map.get(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY1))
//									.append(":")
									.append(map.get(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY2))
									.toString();
        		selectedCodeSet.add(val);
        		codeMapList.add(map);
        	}
        }
        for (Map<String, String> map:checkedCodeMapList) {
        	if (map != null
//        			&& map.containsKey(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY1)
        			&& map.containsKey(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY2)) {
        		String val = new StringBuffer()
//									.append(map.get(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY1))
//									.append(":")
									.append(map.get(AuthUserCodeListController.CALL_PARAMETER_DATA_KEY2))
									.toString();
        		checkedCodeSet.add(val);
        		//if (!selectedCodeSet.contains(val)) codeMapList.add(map);
        	}
        }

        if (searchFlag || codeMapList.size() > 0) {
			// 「\」「%」をエスケープ
			if (searchUserCode.indexOf("\\") >= 0) searchUserCode = searchUserCode.replace("\\", "\\\\");
			if (searchUserCode.indexOf("%") >= 0) searchUserCode = searchUserCode.replace("%", "\\%");
			if (searchUserName.indexOf("\\") >= 0) searchUserName = searchUserName.replace("\\", "\\\\");
			if (searchUserName.indexOf("%") >= 0) searchUserName = searchUserName.replace("%", "\\%");
			vUserListEntityList = vUserMapper.selectVUserByAuthUserCodeList(codeMapList
																			, searchFlag
																			, searchUserCode
																			, searchUserName
																			, searchStartDateYmd
																			, searchEndDateYmd);
        }
		if (vUserListEntityList != null) {
			List<AuthUserCodeListDto> list = new ArrayList<AuthUserCodeListDto>();
			for (VGamenUserEntity vUserEntity : vUserListEntityList) {
				AuthUserCodeListDto dto = new AuthUserCodeListDto();
				dto.setUserCode(vUserEntity.getUserId());
				dto.setUserNameJp(vUserEntity.getNameJp());
				dto.setDepartmentName(vUserEntity.getOrganizationNameJp());
				dto.setStartDateYmd(dateToString(vUserEntity.getStartDate()));
				dto.setEndDateYmd(dateToString(vUserEntity.getEndDate()));
        		String val = new StringBuffer()
        							.append(dto.getUserCode())
        							.toString();
				if (selectedCodeSet.contains(val)) {
					// 選択済みのデータ
					dto.setSelectedFlag(true);
				} else {
					// 未選択のデータ
					dto.setSelectedFlag(false);
				}
				if (checkedCodeSet.contains(val)) {
					// チェックのデータ
					dto.setCheckedFlag(true);
				} else {
					// 未チェックのデータ
					dto.setCheckedFlag(false);
				}
				if (dto.isSelectedFlag()) {
					result.add(dto);
				} else {
					list.add(dto);
				}
			}
			result.addAll(list);
		}

		LogService.info(AuthOrgCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "ユーザー情報検索処理", "正常終了");
    	return result;
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
