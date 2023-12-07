package jp.co.axio.masterMentsetSystem.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import jp.co.axio.masterMentsetSystem.dto.UserOtherInfoDto;
import jp.co.axio.masterMentsetSystem.model.VGamenUserEntity;

/**
 * 利用者詳細画面
 * その他項目
 * 案件によって変更があるため、別ソースとして管理する
 */

@Service
public class UserSetOtherService {


    /**
     * その他項目取得
     * @param vo
     * @return
     */
    public List<UserOtherInfoDto> userOtherInfoList(VGamenUserEntity vo) {

        // その他情報一覧
		List<UserOtherInfoDto> userOtherInfoList = new ArrayList<UserOtherInfoDto>();
        
        UserOtherInfoDto other = new UserOtherInfoDto();

        // 所属会社名
		other = new UserOtherInfoDto();

		other.setColumnName("所属会社名");

		if (vo != null) {
			other.setValueValue(vo.getCompanyName());
		}
		userOtherInfoList.add(other);

        return userOtherInfoList;
    }

}
