"""
crime_pattern_analysis.py
Dedicated backend service module for AI-Powered Crime Pattern & Similarity Detector.
Performs trend detection, year-over-year spike detection, statistical similarity calculation,
behavioral clustering, and explainable AI crime insights synthesis.
"""

import math
from typing import Dict, List, Any, Optional, Tuple


def get_filter_options(conn) -> Dict[str, Any]:
    """Retrieve available filter options from the database."""
    cursor = conn.cursor()
    
    # 1. Crime types
    crime_rows = cursor.execute("""
        SELECT DISTINCT crime_type 
        FROM crime_statistics 
        WHERE crime_type != 'TOTAL' 
        ORDER BY crime_type
    """).fetchall()
    crimes = [r[0] for r in crime_rows]
    
    # 2. Normalized states
    state_rows = cursor.execute("""
        SELECT DISTINCT state 
        FROM crime_statistics 
        ORDER BY state
    """).fetchall()
    state_dict = {}
    for r in state_rows:
        raw_state = r[0].strip()
        upper_state = raw_state.upper()
        if upper_state not in state_dict:
            state_dict[upper_state] = raw_state
    states = sorted(list(state_dict.keys()))
    
    # 3. Year range bounds
    year_row = cursor.execute("""
        SELECT MIN(year), MAX(year) 
        FROM crime_statistics
    """).fetchone()
    min_year = year_row[0] if year_row and year_row[0] else 2001
    max_year = year_row[1] if year_row and year_row[1] else 2013
    
    return {
        "crimes": crimes,
        "states": states,
        "min_year": min_year,
        "max_year": max_year,
        "years": list(range(min_year, max_year + 1))
    }


def get_districts_for_state(conn, state: str) -> List[str]:
    """Get all unique districts for a selected state."""
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT DISTINCT district 
        FROM crime_statistics 
        WHERE UPPER(state) = ? AND UPPER(district) NOT LIKE '%TOTAL%'
        ORDER BY district
    """, (state.upper().strip(),)).fetchall()
    return [r[0].strip() for r in rows if r[0].strip()]


def get_yearly_series(
    conn,
    crime_type: str,
    state: str,
    district: Optional[str] = None,
    start_year: int = 2001,
    end_year: int = 2013
) -> Dict[int, int]:
    """Extract full continuous annual frequency series for a location."""
    cursor = conn.cursor()
    query = """
        SELECT year, SUM(case_count) as total
        FROM crime_statistics
        WHERE crime_type = ? AND UPPER(state) = ? AND year BETWEEN ? AND ?
    """
    params: List[Any] = [crime_type, state.upper().strip(), start_year, end_year]
    
    if district and district.strip():
        query += " AND UPPER(district) = ?"
        params.append(district.upper().strip())
        
    query += " GROUP BY year ORDER BY year"
    rows = cursor.execute(query, params).fetchall()
    
    # Fill continuous years to prevent missing points
    series = {y: 0 for y in range(start_year, end_year + 1)}
    for r in rows:
        series[r[0]] = int(r[1])
    return series


def analyze_trend(series: Dict[int, int]) -> Dict[str, Any]:
    """
    Quantifies trajectory slope, overall percent growth, peak year,
    and classifies trend as Increasing, Decreasing, or Stable.
    """
    years = sorted(series.keys())
    if not years:
        return {
            "status": "Insufficient Data",
            "direction": "Unknown",
            "badge_color": "secondary",
            "total_cases": 0,
            "net_change_pct": 0.0,
            "slope": 0.0,
            "peak_year": None,
            "peak_value": 0,
            "lowest_year": None,
            "lowest_value": 0,
            "description": "No historical records available for this selection."
        }
        
    values = [series[y] for y in years]
    total_cases = sum(values)
    n = len(years)
    
    # Peak and lowest
    peak_val = max(values)
    lowest_val = min(values)
    peak_yr = years[values.index(peak_val)]
    lowest_yr = years[values.index(lowest_val)]
    
    start_val = values[0]
    end_val = values[-1]
    
    if start_val > 0:
        net_change_pct = round(((end_val - start_val) / start_val) * 100.0, 1)
    elif end_val > 0:
        net_change_pct = 100.0
    else:
        net_change_pct = 0.0

    # Calculate linear regression slope (cases per year)
    if n >= 2:
        x_mean = sum(years) / n
        y_mean = sum(values) / n
        num = sum((x - x_mean) * (y - y_mean) for x, y in zip(years, values))
        den = sum((x - x_mean) ** 2 for x in years)
        slope = num / den if den != 0 else 0.0
        rel_slope_pct = (slope / y_mean * 100.0) if y_mean > 0 else 0.0
    else:
        slope = 0.0
        rel_slope_pct = 0.0

    # Classify direction
    if rel_slope_pct > 2.0 or (net_change_pct >= 20.0 and rel_slope_pct > 0):
        direction = "Increasing"
        badge_color = "danger"
        icon = "📈"
        description = f"Cases demonstrate an overall increasing trajectory with an annualized trend slope of +{rel_slope_pct:.1f}%."
    elif rel_slope_pct < -2.0 or (net_change_pct <= -20.0 and rel_slope_pct < 0):
        direction = "Decreasing"
        badge_color = "success"
        icon = "📉"
        description = f"Cases demonstrate a clear downward trend with a reduction slope of {rel_slope_pct:.1f}% per year."
    else:
        direction = "Stable"
        badge_color = "info"
        icon = "➡️"
        description = "Cases remained relatively stable over the selected period with minimal secular drift."

    return {
        "status": "Success",
        "direction": direction,
        "icon": icon,
        "badge_color": badge_color,
        "total_cases": total_cases,
        "net_change_pct": net_change_pct,
        "slope": round(slope, 2),
        "annualized_pct": round(rel_slope_pct, 1),
        "peak_year": peak_yr,
        "peak_value": peak_val,
        "lowest_year": lowest_yr,
        "lowest_value": lowest_val,
        "description": description
    }


def detect_spikes(
    series: Dict[int, int],
    threshold_pct: float = 20.0,
    min_delta_cases: int = 25
) -> List[Dict[str, Any]]:
    """
    Detects unusual year-over-year surge jumps (>= threshold_pct) or sharp drops (<= -threshold_pct).
    """
    years = sorted(series.keys())
    spikes = []
    
    for i in range(1, len(years)):
        prev_yr = years[i - 1]
        curr_yr = years[i]
        prev_val = series[prev_yr]
        curr_val = series[curr_yr]
        delta_cases = curr_val - prev_val
        
        if prev_val == 0:
            if curr_val >= min_delta_cases:
                spikes.append({
                    "year": curr_yr,
                    "prev_year": prev_yr,
                    "type": "Spike",
                    "badge_color": "danger",
                    "pct_change": 100.0,
                    "delta_cases": delta_cases,
                    "curr_val": curr_val,
                    "prev_val": prev_val,
                    "headline": f"⚠️ Sudden Emergence in {curr_yr}",
                    "detail": f"Jumped from 0 to {curr_val:,} cases (+{delta_cases:,} cases)."
                })
            continue

        pct_change = ((curr_val - prev_val) / prev_val) * 100.0
        
        if pct_change >= threshold_pct and delta_cases >= min_delta_cases:
            spikes.append({
                "year": curr_yr,
                "prev_year": prev_yr,
                "type": "Spike",
                "badge_color": "danger",
                "pct_change": round(pct_change, 1),
                "delta_cases": delta_cases,
                "curr_val": curr_val,
                "prev_val": prev_val,
                "headline": f"⚠️ Unusual Crime Spike in {curr_yr}",
                "detail": f"Increased by +{pct_change:.1f}% compared to {prev_yr} (+{delta_cases:,} cases)."
            })
        elif pct_change <= -threshold_pct and abs(delta_cases) >= min_delta_cases:
            spikes.append({
                "year": curr_yr,
                "prev_year": prev_yr,
                "type": "Drop",
                "badge_color": "success",
                "pct_change": round(pct_change, 1),
                "delta_cases": delta_cases,
                "curr_val": curr_val,
                "prev_val": prev_val,
                "headline": f"📉 Significant Crime Reduction in {curr_yr}",
                "detail": f"Dropped by {abs(pct_change):.1f}% compared to {prev_yr} ({delta_cases:,} cases)."
            })

    spikes.sort(key=lambda s: abs(s["pct_change"]), reverse=True)
    return spikes


def _pearson_correlation(v1: List[float], v2: List[float]) -> float:
    """Calculates standard Pearson correlation coefficient between two vectors."""
    n = len(v1)
    if n < 2:
        return 0.0
    mean1 = sum(v1) / n
    mean2 = sum(v2) / n
    num = sum((a - mean1) * (b - mean2) for a, b in zip(v1, v2))
    den1 = math.sqrt(sum((a - mean1) ** 2 for a in v1))
    den2 = math.sqrt(sum((b - mean2) ** 2 for b in v2))
    if den1 == 0.0 or den2 == 0.0:
        return 0.0
    return num / (den1 * den2)


def calculate_similarity_rankings(
    conn,
    crime_type: str,
    target_state: str,
    target_district: Optional[str] = None,
    start_year: int = 2001,
    end_year: int = 2013,
    top_n: int = 8
) -> Tuple[List[Dict[str, Any]], Dict[str, List[int]]]:
    """
    Compares the selected location against other locations across the full annual trend.
    Uses Pearson correlation coefficient (r) mapped to percentage [0, 100%] to measure
    shape & co-movement similarity.
    """
    years = list(range(start_year, end_year + 1))
    target_series = get_yearly_series(conn, crime_type, target_state, target_district, start_year, end_year)
    target_vec = [float(target_series[y]) for y in years]
    target_sum = sum(target_vec)
    
    if target_sum == 0:
        return [], {}

    cursor = conn.cursor()
    ranked = []
    comparison_series: Dict[str, List[int]] = {}

    if target_district and target_district.strip():
        district_rows = cursor.execute("""
            SELECT DISTINCT district 
            FROM crime_statistics 
            WHERE UPPER(state) = ? AND UPPER(district) != ? AND UPPER(district) NOT LIKE '%TOTAL%'
        """, (target_state.upper().strip(), target_district.upper().strip())).fetchall()
        
        candidates = [r[0].strip() for r in district_rows if r[0].strip()]
        for cand in candidates:
            cand_series = get_yearly_series(conn, crime_type, target_state, cand, start_year, end_year)
            cand_vec = [float(cand_series[y]) for y in years]
            if sum(cand_vec) == 0:
                continue
            r = _pearson_correlation(target_vec, cand_vec)
            if r <= 0:
                continue
            score_pct = round(r * 100.0, 1)
            
            pattern_desc = _get_pattern_description(target_vec, cand_vec, r)
            ranked.append({
                "location": f"{cand} ({target_state})",
                "name": cand,
                "score": score_pct,
                "r_val": round(r, 3),
                "pattern": pattern_desc,
                "series": [int(v) for v in cand_vec]
            })
    else:
        state_rows = cursor.execute("""
            SELECT DISTINCT UPPER(state) 
            FROM crime_statistics 
            WHERE UPPER(state) != ?
        """, (target_state.upper().strip(),)).fetchall()
        
        candidates = [r[0] for r in state_rows]
        for cand in candidates:
            cand_series = get_yearly_series(conn, crime_type, cand, None, start_year, end_year)
            cand_vec = [float(cand_series[y]) for y in years]
            if sum(cand_vec) == 0:
                continue
            r = _pearson_correlation(target_vec, cand_vec)
            if r <= 0:
                continue
            score_pct = round(r * 100.0, 1)
            
            pattern_desc = _get_pattern_description(target_vec, cand_vec, r)
            ranked.append({
                "location": cand,
                "name": cand,
                "score": score_pct,
                "r_val": round(r, 3),
                "pattern": pattern_desc,
                "series": [int(v) for v in cand_vec]
            })

    ranked.sort(key=lambda x: x["score"], reverse=True)
    top_results = ranked[:top_n]
    
    for item in top_results[:4]:
        comparison_series[item["name"]] = item["series"]
        
    return top_results, comparison_series


def _get_pattern_description(v1: List[float], v2: List[float], r: float) -> str:
    """Provides a human-readable qualitative description of shared patterns."""
    if r >= 0.90:
        return "Strongly synchronized multi-year trajectory"
    elif r >= 0.80:
        return "Parallel growth and decline pattern"
    elif r >= 0.65:
        return "Consistent trend alignment with minor phase variance"
    elif r >= 0.50:
        return "Moderate directional correlation"
    else:
        return "Similar cyclical fluctuations"


def detect_crime_clusters(
    conn,
    crime_type: str,
    start_year: int = 2001,
    end_year: int = 2013
) -> Dict[str, Any]:
    """
    Groups states into 4 interpretable behavioral crime clusters based on
    volume magnitude, trajectory growth slope, and volatility.
    """
    cursor = conn.cursor()
    state_rows = cursor.execute("""
        SELECT DISTINCT UPPER(state) 
        FROM crime_statistics
    """).fetchall()
    states = [r[0] for r in state_rows]
    years = list(range(start_year, end_year + 1))
    
    profiles = []
    for st in states:
        series = get_yearly_series(conn, crime_type, st, None, start_year, end_year)
        vals = [series[y] for y in years]
        total = sum(vals)
        if total == 0:
            continue
            
        n = len(vals)
        mean_val = total / n
        start_val = vals[0]
        end_val = vals[-1]
        
        # Growth
        if start_val > 0:
            growth = ((end_val - start_val) / start_val) * 100.0
        else:
            growth = 50.0 if end_val > 0 else 0.0
            
        # Volatility
        var = sum((x - mean_val) ** 2 for x in vals) / n
        std = math.sqrt(var)
        cv = (std / mean_val) if mean_val > 0 else 0.0
        
        profiles.append({
            "state": st,
            "mean": mean_val,
            "growth": growth,
            "cv": cv,
            "total": total
        })

    if not profiles:
        return {}

    volumes = sorted([p["mean"] for p in profiles])
    med_vol = volumes[len(volumes) // 2]
    
    cluster_1 = []  # High Volume & Surging
    cluster_2 = []  # High Volume & Controlled
    cluster_3 = []  # Moderate Volume & Stable
    cluster_4 = []  # Low Volume with Volatile Spikes

    for p in profiles:
        st = p["state"]
        if p["mean"] >= med_vol:
            if p["growth"] >= 15.0:
                cluster_1.append(st)
            else:
                cluster_2.append(st)
        else:
            if p["cv"] >= 0.40:
                cluster_4.append(st)
            else:
                cluster_3.append(st)

    return {
        "Cluster 1: High Volume & Surging Growth": {
            "icon": "🔴",
            "badge": "danger",
            "description": "High case volume experiencing rapid multi-year escalation.",
            "members": sorted(cluster_1)
        },
        "Cluster 2: High Volume & Stabilized / Declining": {
            "icon": "🟢",
            "badge": "success",
            "description": "High case volume areas that have achieved downward or controlled trends.",
            "members": sorted(cluster_2)
        },
        "Cluster 3: Moderate Volume & Stable Pattern": {
            "icon": "🟣",
            "badge": "primary",
            "description": "Moderate crime presence with predictable, low-volatility historical lines.",
            "members": sorted(cluster_3)
        },
        "Cluster 4: Low Volume with Volatile Spikes": {
            "icon": "🟠",
            "badge": "warning",
            "description": "Lower overall case numbers marked by sudden, sporadic surge spikes.",
            "members": sorted(cluster_4)
        }
    }


def generate_ai_insights(
    crime_type: str,
    location_name: str,
    trend: Dict[str, Any],
    spikes: List[Dict[str, Any]],
    similarities: List[Dict[str, Any]],
    clusters: Dict[str, Any],
    start_year: int,
    end_year: int
) -> List[Dict[str, str]]:
    """
    Synthesizes intelligent, plain-English, explainable insights derived strictly
    from mathematical metrics and verifiable calculations.
    """
    insights = []

    # 1. Trend summary insight
    direction = trend.get("direction", "Stable")
    net_pct = trend.get("net_change_pct", 0.0)
    sign = "+" if net_pct > 0 else ""
    insights.append({
        "type": "Trend Overview",
        "icon": trend.get("icon", "📈"),
        "text": (
            f"Between {start_year} and {end_year}, {crime_type} in {location_name} exhibited an "
            f"overall {direction.lower()} pattern with a net shift of {sign}{net_pct}%."
        )
    })

    # 2. Peak & Lowest Year Insight
    peak_yr = trend.get("peak_year")
    peak_val = trend.get("peak_value", 0)
    low_yr = trend.get("lowest_year")
    low_val = trend.get("lowest_value", 0)
    if peak_yr and low_yr:
        insights.append({
            "type": "Historical Extremes",
            "icon": "🎯",
            "text": (
                f"Peak incidence was recorded in {peak_yr} with {peak_val:,} cases, "
                f"while the lowest registered mark was {low_val:,} cases in {low_yr}."
            )
        })

    # 3. Top Pattern Twin Insight
    if similarities:
        top_twin = similarities[0]
        score = top_twin["score"]
        loc = top_twin["location"]
        desc = top_twin["pattern"]
        insights.append({
            "type": "Pattern Similarity",
            "icon": "🔗",
            "text": (
                f"{location_name} shares its closest mathematical crime pattern with {loc} "
                f"({score}% similarity score) — {desc.lower()}."
            )
        })
        if len(similarities) >= 3:
            runner_ups = f"{similarities[1]['location']} ({similarities[1]['score']}%) and {similarities[2]['location']} ({similarities[2]['score']}%)"
            insights.append({
                "type": "Secondary Correlates",
                "icon": "👥",
                "text": f"Secondary behavioral correlates also include {runner_ups}."
            })

    # 4. Spike & Anomaly Insight
    if spikes:
        top_spike = spikes[0]
        insights.append({
            "type": "Spike Alert",
            "icon": "⚠️",
            "text": (
                f"Notable anomaly detected in {top_spike['year']}: "
                f"Cases jumped by {top_spike['pct_change']}% compared to {top_spike['prev_year']} "
                f"(an increase of {top_spike['delta_cases']:,} cases)."
            )
        })
    else:
        insights.append({
            "type": "Stability Indicator",
            "icon": "🛡️",
            "text": "No extreme single-year volatility spikes exceeding 20% were observed across the selected period."
        })

    # 5. Cluster placement insight
    target_clean = location_name.upper().strip()
    matched_cluster = None
    for c_name, c_info in clusters.items():
        if any(target_clean == m.upper().strip() for m in c_info.get("members", [])):
            matched_cluster = c_name
            break
            
    if matched_cluster:
        insights.append({
            "type": "Cluster Placement",
            "icon": "🏷️",
            "text": f"{location_name} is statistically classified into '{matched_cluster}' based on historical magnitude and growth trajectory."
        })

    return insights


def run_full_analysis(
    conn,
    crime_type: str = "THEFT",
    state: str = "MAHARASHTRA",
    district: Optional[str] = None,
    start_year: int = 2001,
    end_year: int = 2013
) -> Dict[str, Any]:
    """Top-level orchestrator returning comprehensive pattern analysis payload."""
    if start_year > end_year:
        start_year, end_year = end_year, start_year
        
    loc_display = f"{district}, {state}" if district and district.strip() else state

    # 1. Target time series
    series = get_yearly_series(conn, crime_type, state, district, start_year, end_year)
    years = sorted(series.keys())
    counts = [series[y] for y in years]

    # 2. Trend analysis
    trend = analyze_trend(series)

    # 3. Spike detection
    spikes = detect_spikes(series)

    # 4. Similarities
    similarities, comp_series = calculate_similarity_rankings(
        conn, crime_type, state, district, start_year, end_year, top_n=8
    )

    # 5. Clusters
    clusters = detect_crime_clusters(conn, crime_type, start_year, end_year)

    # 6. AI Insights
    insights = generate_ai_insights(
        crime_type, loc_display, trend, spikes, similarities, clusters, start_year, end_year
    )

    return {
        "crime_type": crime_type,
        "state": state,
        "district": district or "",
        "location_display": loc_display,
        "start_year": start_year,
        "end_year": end_year,
        "years": years,
        "counts": counts,
        "trend": trend,
        "spikes": spikes,
        "similarities": similarities,
        "comparison_series": comp_series,
        "clusters": clusters,
        "insights": insights
    }
