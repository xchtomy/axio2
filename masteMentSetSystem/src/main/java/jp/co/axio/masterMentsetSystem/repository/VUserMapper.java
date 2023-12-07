package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jp.co.axio.masterMentsetSystem.controller.UserListForm;
import jp.co.axio.masterMentsetSystem.dto.UserAnnCmbOrgDto;
import jp.co.axio.masterMentsetSystem.dto.UserCareerInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserGrpDto;
import jp.co.axio.masterMentsetSystem.dto.UserManCmbOrgDto;
import jp.co.axio.masterMentsetSystem.dto.UserOtherInfoDto;
import jp.co.axio.masterMentsetSystem.dto.UserPositionInfoDto;
import jp.co.axio.masterMentsetSystem.model.MUserOrgBeforeEntity;
import jp.co.axio.masterMentsetSystem.model.VGamenUserEntity;

@Mapper
public interface VUserMapper {

	List<VGamenUserEntity> selectUserList(UserListForm form);

	List<VGamenUserEntity> getCsvList(UserListForm form);

	String getUserCount(UserListForm form);

	VGamenUserEntity getUser(VGamenUserEntity entity);

	List<UserGrpDto> getUserGrp(String userId);

	List<UserAnnCmbOrgDto> getAnnCmbOrg(String userId);

	List<UserManCmbOrgDto> getManCmbOrg(String userId);

	List<UserPositionInfoDto> getPosList();

	List<UserCareerInfoDto> getCareerInfo(String userId);

	List<UserOtherInfoDto> getOthersInfo(String userId);

	int delUserOrgBefore(MUserOrgBeforeEntity entity);

	int updUserOrgBefore(MUserOrgBeforeEntity entity);

	int insUserOrgBefore(MUserOrgBeforeEntity entity);

	List<MUserOrgBeforeEntity> getUserOrgBefore(String userId);

	List<VGamenUserEntity> selectVUserByAuthUserCodeList(
															 @Param("codeMapList") List<Map<String, String>> codeMapList
															,@Param("searchFlag") boolean searchFlag
															,@Param("searchUserCode") String searchUserCode
															,@Param("searchUserName") String searchUserName
															,@Param("searchStartDateYmd") String searchStartDateYmd
															,@Param("searchEndDateYmd") String searchEndDateYmd
															);
}