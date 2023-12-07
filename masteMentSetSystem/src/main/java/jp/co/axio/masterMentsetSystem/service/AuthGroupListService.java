package jp.co.axio.masterMentsetSystem.service;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthGroupListForm;
import jp.co.axio.masterMentsetSystem.dto.AuthGroupListDto;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.repository.MGroupEntityMapper;

/**
 * グループ一覧画面サービスクラス
 *
 * @author AXIO
 * @version 1.0
 */
@Service
public class AuthGroupListService {


    @Autowired
    MGroupEntityMapper mGroupEntityMapper;

    /**
     * グループIDでグループ情報を取得する
     *
     * @param groupId グループID
     * @return record グループ情報
     * @throws Exception
     */
    @Transactional
    public MGroupEntity selectByGroupId (String groupId) throws Exception{
        LogService.info("グループ検索一覧画面", "selectByGroupId", "グループIDでグループ情報取得", "開始");

        MGroupEntity record = mGroupEntityMapper.selectByPrimaryKey(groupId);

        LogService.info("グループ検索一覧画面", "selectByGroupId", "グループIDでグループ情報取得", "正常終了");
    	return record;
    }


	/**
	* グループ情報一覧検索
	* @param form 画面の入力情報
	* @return List<MGroupEntity> 取得結果
	*/
	@Transactional
	public List<AuthGroupListDto> selectGroupList (AuthGroupListForm form) throws Exception {
		LogService.info("グループ検索一覧画面", "selectGroupList", "グループ一覧取得", "開始");

		String groupId = null;
		String groupNameEn = null;
		String groupNameJp = null;
		String groupNote = null;
		String refDate = null;

		if (StringUtils.isNotBlank(form.getDailogGroupId())) {
			groupId = "%" + StringUtils.trim(form.getDailogGroupId()) + "%";
		}
		if (StringUtils.isNotBlank(form.getDailogGroupNameEn())) {
			groupNameEn = "%" + StringUtils.trim(form.getDailogGroupNameEn()) + "%";
		}
		if (StringUtils.isNotBlank(form.getDailogGroupNameJp())) {
			groupNameJp = "%" + StringUtils.trim(form.getDailogGroupNameJp()) + "%";
		}
		if (StringUtils.isNotBlank(form.getDailogGroupNote())) {
			groupNote = "%" + StringUtils.trim(form.getDailogGroupNote()) + "%";
		}
		if (StringUtils.isNotBlank(form.getDailogStartDate())) {
			refDate = form.getDailogStartDate();
		}
		List<AuthGroupListDto> rt = mGroupEntityMapper.selectGroupList(groupId, groupNameEn, groupNameJp, groupNote, refDate);

		LogService.info("グループ検索一覧画面", "selectGroupList", "グループ一覧取得", "正常終了");
		return rt;
	}

}
