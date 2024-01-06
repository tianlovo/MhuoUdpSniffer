package com.tlovo.analyze.packet;

import com.google.protobuf.UnknownFieldSet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Protobuf消息数据类
 * <br/>
 * 相当于整个消息类
 */
public class ProtoMessage {
    /** 消息名称 */
    private String messageName = "Unknown";

    /** 成员变量 */
    private List<ProtoField> fields;

    /** 嵌套消息成员变量 */
    private Map<Integer, ProtoMessage> msgFields;

    public ProtoMessage() {
        fields = new ArrayList<>();
        msgFields = new HashMap<>();
    }

    public ProtoMessage(String messageName) {
        this.messageName = messageName;
        fields = new ArrayList<>();
        msgFields = new HashMap<>();
    }

    public void parseFrom(UnknownFieldSet fieldSet) {
        fields.clear();
        msgFields.clear();

        fieldSet.asMap().forEach((tag, field) -> {
            if (!field.getGroupList().isEmpty()) {
                // 嵌套消息处理
                field.getGroupList().forEach(ufs -> {
                    ProtoMessage msg = new ProtoMessage();
                    msg.parseFrom(ufs);
                    msgFields.put(tag, msg);
                });
            } else {
                fields.add(new ProtoField(tag, field));
            }
        });
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("消息名称：").append(messageName).append("\n");

        fields.forEach(field -> sb.append(field.toString()).append("\n"));
        msgFields.forEach((tag, field) -> {
            sb.append("[UnknownSubField:").append(tag).append("]\n");
            sb.append(field.toString()).append("\n");
        });

        return sb.toString();
    }
}
