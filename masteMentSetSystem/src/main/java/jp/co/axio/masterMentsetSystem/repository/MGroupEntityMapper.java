package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.jdbc.SQL;

import jp.co.axio.masterMentsetSystem.dto.AuthGroupListDto;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MGroupEntityExample;

@Mapper
public interface MGroupEntityMapper {
    long countByExample(MGroupEntityExample example);

    int deleteByExample(MGroupEntityExample example);

    int deleteByPrimaryKey(String groupId);

    int insert(MGroupEntity record);

    int insertSelective(MGroupEntity record);

    List<MGroupEntity> selectByExample(MGroupEntityExample example);

    MGroupEntity selectByPrimaryKey(String groupId);

    int updateByExampleSelective(@Param("record") MGroupEntity record, @Param("example") MGroupEntityExample example);

    int updateByExample(@Param("record") MGroupEntity record, @Param("example") MGroupEntityExample example);

    int updateByPrimaryKeySelective(MGroupEntity record);

    int updateByPrimaryKey(MGroupEntity record);

    /**
     * 繧ｰ繝ｫ繝ｼ繝励ｒ辟｡蜉ｹ蛹悶☆繧�
     *
     * @param groupId
     * @return
     */
    int invalidByKey(String groupId);

    /**
     * 菫晏ｭ伜�ｦ逅�縺ｮ譖ｴ譁ｰ
     *
     * @param record
     * @return
     */
    int updateByInput(MGroupEntity record);

    /**
     * 繧ｰ繝ｫ繝ｼ繝悠D縺ｮ謗｡逡ｪ
     *
     * @return
     */
    MGroupEntity getNewId();

    /**
     * グループ名称でグループ情報を取得する
     *
     *@param groupNameJp
     * @return
     */
    MGroupEntity getByGroupNameJp(@Param("groupNameJp")String groupNameJp);

    /**
     * グループ名称で有効なグループ情報を取得する
     *
     *@param groupNameJp
     * @return
     */
    MGroupEntity getValidByName(@Param("groupNameJp")String groupNameJp);

    /**
     * 讀懃ｴ｢譚｡莉ｶ縺ｧ繧ｰ繝ｫ繝ｼ繝嶺ｸ�隕ｧ繧貞叙蠕励☆繧�
     *
     * @param groupId
     * @param groupNameEn
     * @param groupNameJp
     * @param groupNote
     * @param refDate
     * @return
     */
    @SelectProvider(type = GroupSqlProvider.class, method = "selectGroupList")
    public List<AuthGroupListDto> selectGroupList(
    			@Param("groupId") String groupId,
    			@Param("groupNameEn") String groupNameEn,
    			@Param("groupNameJp") String groupNameJp,
    			@Param("groupNote") String groupNote,
    			@Param("refDate") String refDate);

    static class GroupSqlProvider  extends SQL {

        public  String  selectGroupList(
    			@Param("groupId") String groupId,
    			@Param("groupNameEn") String groupNameEn,
    			@Param("groupNameJp") String groupNameJp,
    			@Param("groupNote") String groupNote,
    			@Param("refDate") String refDate) {

        	StringBuilder sql = new StringBuilder(
            		"SELECT DISTINCT group_id, group_name_en,group_name_jp, note, to_char(start_date, 'YYYY/MM/DD') as start_date, to_char(end_date, 'YYYY/MM/DD') as end_date FROM m_group WHERE invalid_flag = '0'");
            String orderby = " order by group_id, start_date,  end_date ";

            if (groupId != null && groupId.length() > 0) {
            	sql.append(" and group_id like #{groupId} ");
            }
            if (groupNameEn != null && groupNameEn.length() > 0) {
            	sql.append(" and group_name_en like #{groupNameEn} ");
            }
            if (groupNameJp != null && groupNameJp.length() > 0) {
            	sql.append(" and group_name_jp like #{groupNameJp} ");
            }
            if (groupNote != null && groupNote.length() > 0) {
            	sql.append(" and note like #{groupNote} ");
            }
            if (StringUtils.isNotBlank(refDate)) {
            	sql.append(" and to_date(#{refDate}, 'yyyy/MM/dd')  between start_date and end_date ");
            }
            return sql.toString() + orderby;
        }
    }

}