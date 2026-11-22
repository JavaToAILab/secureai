package io.github.javatoailab.secureai.api;

import io.github.javatoailab.secureai.audit.AuditLog;
import io.github.javatoailab.secureai.audit.AuditRecord;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Read-only audit views for admin tenants. */
@RestController
@RequestMapping("/admin/audit")
public class AuditController {

    private final AuditLog audit;

    public AuditController(AuditLog audit) {
        this.audit = audit;
    }

    @GetMapping("/recent")
    public List<AuditRecord> recent(@RequestParam(defaultValue = "50") int limit) {
        List<AuditRecord> all = audit.recent();
        return all.subList(Math.max(0, all.size() - Math.min(limit, 1000)), all.size());
    }

    /** Recomputes the hash chain over the retained window. */
    @GetMapping("/verify")
    public Map<String, Object> verify() {
        List<AuditRecord> records = audit.recent();
        Optional<Long> broken = AuditLog.firstBrokenLink(records);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("records", records.size());
        out.put("intact", broken.isEmpty());
        out.put("firstBrokenSeq", broken.orElse(null));
        out.put("sinkFailures", audit.sinkFailures());
        return out;
    }
}
